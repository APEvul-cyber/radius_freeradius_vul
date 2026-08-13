# EAP-Message (Type 79) without Message-Authenticator

Access-Request attributes are not MACed. A MITM can change this attribute and the NAS still accepts the Access-Accept.

## Reproduce

`poc/scripts/e2e_all_pocs.py`

**Expected:** require Message-Authenticator / RADIUS/1.1 / TLS.

https://github.com/APEvul-cyber/radius_freeradius_vul/tree/main/eap-message
