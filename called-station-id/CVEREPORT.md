# RADIUS Access-Request: Called-Station-Id (Type 30) service escalation

**Affected:** RADIUS (RFC 2865) as implemented by FreeRADIUS; lab MITM on Access-Request.  
**CWE:** CWE-345

MITM rewrites Called-Station-Id (e.g. LOW-SERVICE → HIGH-SERVICE). Server authorizes the new service. NAS checks only the Response Authenticator. Access-Request attributes have no integrity.

RFC 2865 does not integrity-protect Access-Request attributes. Attackers on the NAS–server path use that. File it as a CVE against deployments that still accept unsigned Access-Request (no Message-Authenticator / no RADIUS/1.1 / no TLS).

## Reproduce

`poc/scripts/e2e_all_pocs.py` and `poc/scripts/mitm_proxy.py`.

**Actual:** attribute change is invisible to the NAS Response Authenticator check.  
**Expected:** require Message-Authenticator (or RADIUS over TLS) on every Access-Request; drop packets that omit it.

## References

- RFC 2865, RFC 2869, RFC 3579, RFC 9427
- CVE-2024-3596
- https://github.com/APEvul-cyber/radius_freeradius_vul/tree/main/called-station-id
