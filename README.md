# radius_freeradius_vul

RFC 2865 Access-Request attributes are not integrity-protected (Request Authenticator is a nonce). An on-path attacker can change NAS-Port-Type, Called-Station-Id, tunnel attributes, etc. without the shared secret.

That is the protocol. FreeRADIUS cannot "fix RFC 2865". Use Message-Authenticator / RADIUS/1.1 / TLS.

PoCs under `poc/` show the MITM. PacketFence-specific trust of `NAS-Port-Type` lives in `packetfence-vlan-escalation`, not here.
