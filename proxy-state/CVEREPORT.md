# RADIUS Access-Request: Proxy-State (Type 33) / Blast-RADIUS

**Affected:** RADIUS (RFC 2865) as implemented by FreeRADIUS; lab MITM on Access-Request.  
**CWE:** CWE-354

CVE-2024-3596. Request Authenticator is a nonce, not a MAC. A MITM can add Proxy-State and attempt an MD5 collision on the response. FreeRADIUS 3.2.3+ rejects Proxy-State without Message-Authenticator. The protocol still allows the class of attack wherever MA is optional.

RFC 2865 does not integrity-protect Access-Request attributes. Attackers on the NAS–server path use that. File it as a CVE against deployments that still accept unsigned Access-Request (no Message-Authenticator / no RADIUS/1.1 / no TLS).

## Reproduce

`poc/scripts/e2e_all_pocs.py` and `poc/scripts/mitm_proxy.py`.

**Actual:** attribute change is invisible to the NAS Response Authenticator check.  
**Expected:** require Message-Authenticator (or RADIUS over TLS) on every Access-Request; drop packets that omit it.

## References

- RFC 2865, RFC 2869, RFC 3579, RFC 9427
- CVE-2024-3596
- https://github.com/APEvul-cyber/radius_freeradius_vul/tree/main/proxy-state
