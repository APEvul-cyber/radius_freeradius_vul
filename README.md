# radius_freeradius_vul

RFC 2865 Access-Request is not integrity-protected. An on-path attacker changes attributes; the NAS still validates the Response Authenticator. That is how attackers get VLAN / tunnel / role changes. Each attribute is a separate impact.

PoCs: `poc/scripts/e2e_all_pocs.py`, `poc/scripts/mitm_proxy.py`.

| Dir | Issue |
|---|---|
| `proxy-state` | Proxy-State (Type 33) / Blast-RADIUS |
| `called-station-id` | Called-Station-Id (Type 30) service escalation |
| `nas-ipv6-address` | NAS-IPv6-Address (Type 95) identity spoof |
| `eap-message` | EAP-Message (Type 79) without Message-Authenticator |
| `framed-protocol` | Framed-Protocol (Type 7) SLIP→PPP escalation |
| `chap-password` | CHAP-Password (Type 3) offline crack |
| `nas-port-type` | NAS-Port-Type (Type 61) Wireless→Ethernet VLAN jump |
| `tunnel-type` | Tunnel-Type (Type 64) L2TP→PPTP downgrade |
| `tunnel-private-group-id` | Tunnel-Private-Group-Id (Type 81) VPN group hijack |
| `coa-tunnel-group` | CoA-Request + Tunnel-Private-Group-Id |
| `vendor-specific` | Vendor-Specific (Type 26) policy injection |
| `tunnel-server-endpoint` | Tunnel-Server-Endpoint (Type 67) redirect |
