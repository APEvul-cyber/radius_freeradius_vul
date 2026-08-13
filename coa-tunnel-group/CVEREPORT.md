# RADIUS Access-Request: CoA-Request + Tunnel-Private-Group-Id

**Affected:** RADIUS (RFC 2865) as implemented by FreeRADIUS; lab MITM on Access-Request.  
**CWE:** CWE-306

A crafted CoA-Request can push a new tunnel group. Port 3799 is off by default in the lab (construct-only). Where CoA is on and unauthenticated, this is a live change.

RFC 2865 does not integrity-protect Access-Request attributes. Attackers on the NAS–server path use that. File it as a CVE against deployments that still accept unsigned Access-Request (no Message-Authenticator / no RADIUS/1.1 / no TLS).

## Reproduce

`poc/scripts/e2e_all_pocs.py` and `poc/scripts/mitm_proxy.py`.

**Actual:** attribute change is invisible to the NAS Response Authenticator check.  
**Expected:** require Message-Authenticator (or RADIUS over TLS) on every Access-Request; drop packets that omit it.

## References

- RFC 2865, RFC 2869, RFC 3579, RFC 9427
- CVE-2024-3596
- https://github.com/APEvul-cyber/radius_freeradius_vul/tree/main/coa-tunnel-group
