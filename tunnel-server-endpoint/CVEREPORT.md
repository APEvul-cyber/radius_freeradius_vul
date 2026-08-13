# RADIUS Access-Request: Tunnel-Server-Endpoint (Type 67) redirect

**Affected:** RADIUS (RFC 2865) as implemented by FreeRADIUS; lab MITM on Access-Request.  
**CWE:** CWE-494

MITM sets Tunnel-Server-Endpoint to an attacker host. NAS builds the tunnel to the attacker after a valid Access-Accept.

RFC 2865 does not integrity-protect Access-Request attributes. Attackers on the NAS–server path use that. File it as a CVE against deployments that still accept unsigned Access-Request (no Message-Authenticator / no RADIUS/1.1 / no TLS).

## Reproduce

`poc/scripts/e2e_all_pocs.py` and `poc/scripts/mitm_proxy.py`.

**Actual:** attribute change is invisible to the NAS Response Authenticator check.  
**Expected:** require Message-Authenticator (or RADIUS over TLS) on every Access-Request; drop packets that omit it.

## References

- RFC 2865, RFC 2869, RFC 3579, RFC 9427
- CVE-2024-3596
- https://github.com/APEvul-cyber/radius_freeradius_vul/tree/main/tunnel-server-endpoint
