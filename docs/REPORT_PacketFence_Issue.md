## Security: VLAN Escalation via NAS-Port-Type Tampering in RADIUS Access-Request

### Description

PacketFence determines whether a connection is "Wired" or "Wireless" by reading the `NAS-Port-Type` attribute directly from the RADIUS `Access-Request` packet (`lib/pf/Connection.pm`, `identifyType()` method). This classification drives VLAN and role assignment — for example, wireless users may be placed in a guest VLAN while wired users get a corporate VLAN.

However, RFC 2865 provides **no integrity protection** for attributes in `Access-Request` packets. The `Request Authenticator` is a random nonce, not a MAC. This means an on-path (MITM) attacker between the NAS and PacketFence can modify `NAS-Port-Type` from `Wireless-802.11` (19) to `Ethernet` (15) without knowing the RADIUS shared secret and without breaking any cryptographic check.

The result: a wireless user is assigned the corporate VLAN instead of the guest VLAN. The NAS successfully validates the `Response Authenticator` in the `Access-Accept`, so the attack is **undetectable** at the RADIUS protocol level.

### Affected Versions

All versions of PacketFence that use `NAS-Port-Type` to determine connection transport type.

### Severity

**High** — Network segmentation bypass. A wireless user can be escalated from a restricted guest VLAN to a privileged corporate VLAN.

### Root Cause (Source Code)

**`lib/pf/Connection.pm` — `identifyType()`:**

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

**`lib/pf/radius.pm`:**

```perl
# Line ~140
my ($nas_port_type, $eap_type, ...) = $switch->parseRequest($radius_request);

# Line ~158 — NAS-Port-Type used to classify connection
$connection->identifyType($nas_port_type, $eap_type, ...);
my $connection_type = $connection->attributesToBackwardCompatible;

# Line ~163 — Different VLAN/role based on classification
if (($connection_type & $WIRELESS) == $WIRELESS) {
    # → guest VLAN, restricted role
}
```

No validation or cross-referencing is performed on `NAS-Port-Type`. The value from the RADIUS `Access-Request` is trusted as-is.

### Attack Scenario

```
1. Wireless user connects to AP
2. NAS (AP) sends Access-Request with NAS-Port-Type = 19 (Wireless-802.11)
3. On-path attacker intercepts UDP packet, changes NAS-Port-Type from 19 to 15 (Ethernet)
   — Single-byte change, no shared secret needed, no MD5 collision needed
4. PacketFence sees NAS-Port-Type = Ethernet → identifyType() sets transport = "Wired"
5. VLAN assignment selects corporate VLAN (e.g., VLAN 10) instead of guest (VLAN 999)
6. Access-Accept with corporate VLAN returned, Response Authenticator is valid
7. NAS verifies Response Authenticator ✓ → applies corporate VLAN to wireless user
8. Wireless user now has corporate network access
```

### Proof of Concept

Full end-to-end PoC with Docker environment: https://github.com/APEvul-cyber/radius_freeradius_vul

The PoC simulates PacketFence's `identifyType()` logic in FreeRADIUS and runs the complete attack chain:

**NAS Simulator → MITM Proxy → RADIUS Server → MITM Proxy → NAS Simulator**

```
STEP 1: Baseline — Wireless user, NAS → Server (no MITM)
  NAS-Port-Type: 19 (Wireless-802.11)
  Response Authenticator valid: ✓
  Assigned VLAN: 999 (guest)

STEP 2: Attack — NAS → MITM → Server (MITM changes NAS-Port-Type)
  NAS sends: NAS-Port-Type = 19 (Wireless-802.11)
  MITM changes to: NAS-Port-Type = 15 (Ethernet)
  Response Authenticator valid: ✓
  Assigned VLAN: 10 (corporate)

✓ ATTACK SUCCESSFUL — VLAN ESCALATION CONFIRMED
```

To reproduce:

```bash
git clone https://github.com/APEvul-cyber/radius_freeradius_vul.git
cd radius_freeradius_vul/poc
docker compose up -d --build
# Wait ~5 seconds for FreeRADIUS
docker compose exec attacker python /scripts/poc_packetfence_vlan_escalation.py
```

### Comparison with CVE-2024-3596 (Blast-RADIUS)

This vulnerability shares the same attack model (on-path MITM on RADIUS/UDP) as CVE-2024-3596 (Blast-RADIUS, CVSS 9.0), but is **simpler to exploit**:

| | CVE-2024-3596 (Blast-RADIUS) | This issue |
|---|---|---|
| Attack model | On-path MITM | On-path MITM (same) |
| Requires MD5 collision | Yes (minutes of computation) | **No** |
| Requires shared secret | No | No |
| Attack complexity | High | **Low** (single byte change) |
| Impact | Forge Access-Accept/Reject | VLAN escalation (guest → corporate) |

### Suggested Fix

1. **Cross-validate `NAS-Port-Type`** against the switch/AP configuration database in PacketFence. In `identifyType()`, compare the received `NAS-Port-Type` with the known capabilities of the NAS identified by `NAS-IP-Address` (which is validated via the RADIUS client configuration). For example, if the NAS is registered as a wireless AP, reject or flag requests claiming `NAS-Port-Type = Ethernet`.

2. **Require `Message-Authenticator`** (RFC 2869) on all `Access-Request` packets. When present, `Message-Authenticator` provides HMAC-MD5 integrity over the entire packet, preventing attribute tampering.

3. **Document the risk** in PacketFence's security guide: deployments using RADIUS/UDP without `Message-Authenticator` or RadSec should be aware that `NAS-Port-Type` (and other `Access-Request` attributes) can be tampered with by on-path attackers.

### References

- [CVE-2024-3596 — Blast-RADIUS](https://www.blastradius.fail/)
- [RFC 2865 — RADIUS](https://datatracker.ietf.org/doc/html/rfc2865) — Section 3: Request Authenticator is a random nonce, not a MAC
- [RFC 6614 — RadSec](https://datatracker.ietf.org/doc/html/rfc6614)
- PacketFence source: [`lib/pf/Connection.pm`](https://github.com/inverse-inc/packetfence/blob/devel/lib/pf/Connection.pm), [`lib/pf/radius.pm`](https://github.com/inverse-inc/packetfence/blob/devel/lib/pf/radius.pm)
