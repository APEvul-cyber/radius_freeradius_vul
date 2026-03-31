# PacketFence NAS-Port-Type VLAN Escalation

## Summary

PacketFence (all versions) uses `NAS-Port-Type` from RADIUS `Access-Request` to determine connection transport type (Wired vs Wireless), which directly drives VLAN and role assignment. Since RFC 2865 provides no integrity protection for `Access-Request` attributes, an on-path MITM attacker can change `NAS-Port-Type` from `Wireless-802.11` (19) to `Ethernet` (15), causing PacketFence to assign the corporate VLAN instead of the guest VLAN.

The NAS validates the `Response Authenticator` successfully — the attack is undetectable at the RADIUS protocol level.

## Affected Software

| Product | Affected | Evidence |
|---------|----------|----------|
| **PacketFence** (inverse-inc) | All versions | Source code: `lib/pf/Connection.pm` |
| **Cisco ISE** | Preconfigured policy sets | `Wired_802.1X` / `Wireless_802.1X` use `NAS-Port-Type` as condition |

## Source Code Evidence

### PacketFence `lib/pf/Connection.pm` — `identifyType()`

```perl
sub identifyType {
    my ( $self, $nas_port_type, $eap_type, $mac, $user_name, $switch, $radius_request ) = @_;

    # NAS-Port-Type from Access-Request directly determines transport type
    if (defined $nas_port_type) {
        $self->transport($nas_port_type =~ /^wireless/i ? "Wireless" : "Wired");
    }
    else {
        $self->transport("Wired");
    }
    ...
}
```

### PacketFence `lib/pf/radius.pm` — VLAN assignment

```perl
# Line ~140: NAS-Port-Type extracted from RADIUS request
my ($nas_port_type, $eap_type, ...) = $switch->parseRequest($radius_request);

# Line ~158: Used to identify connection type
$connection->identifyType($nas_port_type, $eap_type, ...);
my $connection_type = $connection->attributesToBackwardCompatible;

# Line ~163: Different VLAN/role for wired vs wireless
if (($connection_type & $WIRELESS) == $WIRELESS) {
    # → guest VLAN, restricted role
} else {
    # → corporate VLAN, full access role
}
```

No validation is performed on `NAS-Port-Type`. The value from the RADIUS `Access-Request` is trusted as-is.

## Attack Chain

```
1. Wireless user connects to AP
2. NAS (AP) sends Access-Request with NAS-Port-Type=19 (Wireless-802.11)
3. MITM intercepts UDP packet, changes NAS-Port-Type from 19 to 15 (Ethernet)
   - This is a single-byte change in the RADIUS attribute value
   - No shared secret knowledge required
   - No MD5 collision computation required
4. PacketFence receives request, sees NAS-Port-Type=Ethernet
5. identifyType() sets transport="Wired"
6. VLAN assignment logic selects corporate VLAN (e.g., VLAN 10) instead of guest (VLAN 999)
7. Access-Accept returned with corporate VLAN, valid Response Authenticator
8. NAS verifies Response Authenticator ✓ (shared secret not involved in attribute integrity)
9. NAS applies corporate VLAN to wireless user
10. Wireless user now has corporate network access
```

## End-to-End PoC Results

```
STEP 1: Baseline — Wireless user, NAS → Server (no MITM)
  NAS-Port-Type: 19 (Wireless-802.11)
  Response Authenticator valid: ✓
  Assigned VLAN: 999 (guest)
  Filter-Id: guest-restricted

STEP 2: Attack — NAS → MITM → Server (MITM changes NAS-Port-Type)
  NAS sends: NAS-Port-Type=19 (Wireless-802.11)
  MITM changes to: NAS-Port-Type=15 (Ethernet)
  Response Authenticator valid: ✓
  Assigned VLAN: 10 (corporate)
  Filter-Id: corporate-full-access

✓ ATTACK SUCCESSFUL — VLAN ESCALATION CONFIRMED
```

## Comparison with CVE-2024-3596 (Blast-RADIUS)

| | CVE-2024-3596 (Blast-RADIUS) | This vulnerability |
|---|---|---|
| Attack model | On-path MITM | On-path MITM (same) |
| Requires MD5 collision | Yes (minutes of computation) | **No** |
| Requires shared secret | No | No |
| Attack complexity | High | **Low** (single byte change) |
| Impact | Forge Access-Accept from Access-Reject | VLAN escalation (guest → corporate) |
| CVSS (Blast-RADIUS) | 9.0 | — |

## Mitigation

1. **Enforce Message-Authenticator** on all Access-Request packets (RFC 2869)
2. **Do not use NAS-Port-Type as sole input** for VLAN/role assignment — cross-reference with NAS-IP-Address and server-side switch/AP database
3. **Deploy RadSec** (RADIUS over TLS, RFC 6614) for transport integrity
4. **PacketFence-specific**: Add validation in `identifyType()` to cross-check NAS-Port-Type against known switch/AP capabilities from the switch configuration database

## Reproduction

```bash
cd poc/
docker compose up -d --build
# Wait for FreeRADIUS
docker compose exec attacker python /scripts/poc_packetfence_vlan_escalation.py
```
