# RADIUS / FreeRADIUS Security Analysis & PoC

Systematic security analysis of RADIUS protocol (RFC 2865/2868) attribute handling, with end-to-end proof-of-concept exploits validated against FreeRADIUS.

## Overview

This repository contains 12 security analysis cases targeting RADIUS protocol attributes in `Access-Request` and `CoA-Request` packets. Each case includes a detailed threat model, attack procedure, and a representative attack message, along with automated PoC scripts that validate the attack end-to-end.

**Core finding:** RFC 2865 provides **no integrity protection** for attributes in `Access-Request` packets. The Request Authenticator is a random nonce (not a MAC), allowing any on-path attacker to freely modify, add, or remove attributes without detection at the RADIUS protocol level.

## Test Environment

| Component | Detail |
|-----------|--------|
| RADIUS Server | FreeRADIUS (latest, Docker) |
| Attack Framework | Python 3.11 (raw socket, no external RADIUS libs) |
| Architecture | NAS Simulator → MITM Proxy → FreeRADIUS → MITM Proxy → NAS |
| Network | Docker bridge `172.20.0.0/24` |

## Results Summary

### End-to-End Attack Results (NAS → MITM → Server → MITM → NAS)

| # | Attribute | Attack Type | E2E Result | NAS Auth Check | Notes |
|---|-----------|-------------|------------|----------------|-------|
| 1 | Proxy-State (Type 33) | Blast-RADIUS MD5 collision | ✅ Mitigated | Auth ✗ (rejected) | **CVE-2024-3596** — FreeRADIUS 3.2.3+ rejects Proxy-State without Message-Authenticator |
| 2 | Called-Station-Id (Type 30) | MITM service-level escalation | ✅ Attack Success | Auth ✓ | LOW-SERVICE → HIGH-SERVICE, different authorization |
| 3 | NAS-IPv6-Address (Type 95) | MITM NAS identity spoofing | ✅ Attack Success | Auth ✓ | Attribute tampered undetected, auth still passes |
| 4 | EAP-Message (Type 79) | Rogue NAS without Message-Authenticator | ✅ Mitigated | Auth ✗ (rejected) | Modern FreeRADIUS enforces MA for EAP (RFC 3579) |
| 5 | Framed-Protocol (Type 7) | MITM SLIP→PPP privilege escalation | ✅ Attack Success | Auth ✓ | guest-restricted → corp-full-access |
| 6 | CHAP-Password (Type 3) | Passive sniff + offline dictionary crack | ✅ Attack Success | Auth ✓ | Password recovered: `weakpass123` |
| 7 | NAS-Port-Type (Type 61) | MITM Wireless→Ethernet VLAN escalation | ✅ Attack Success | Auth ✓ | VLAN 999 (guest) → VLAN 10 (internal) |
| 8 | Tunnel-Type (Type 64) | MITM L2TP→PPTP tunnel downgrade | ✅ Attack Success | Auth ✓ | Secure tunnel downgraded to weak PPTP |
| 9 | Tunnel-Private-Group-Id (Type 81) | MITM VPN group hijacking | ✅ Attack Success | Auth ✓ | guest-vpn → corp-vpn |
| 10 | CoA + Tunnel-Private-Group-Id | CoA-Request injection | ⚠️ Construct Only | N/A | CoA port (3799) not enabled by default |
| 11 | Vendor-Specific (Type 26) | MITM VSA policy injection | ✅ Attack Success | Auth ✓ | Injected `role=admin` VSA accepted |
| 12 | Tunnel-Server-Endpoint (Type 67) | MITM tunnel redirection | ✅ Attack Success | Auth ✓ | Tunnel endpoint redirected to attacker |

**Key:** "Auth ✓" means the NAS successfully validated the Response Authenticator using the shared secret — the NAS has no way to know the request was tampered with.

### Classification

All 12 cases are classified as **ATTACK**:
- **8 full end-to-end attacks** (#2, 3, 5, 7, 8, 9, 11, 12): MITM tampers attribute → server returns different authorization → NAS validates Response Authenticator ✓ → NAS applies attacker-chosen policy
- **1 passive attack** (#6): Offline CHAP password cracking from sniffed packets
- **1 known CVE, mitigated** (#1): CVE-2024-3596 (Blast-RADIUS), patched in FreeRADIUS 3.2.3+
- **1 mitigated by default** (#4): RFC 3579 Message-Authenticator enforcement
- **1 construction-verified** (#10): CoA packet construction correct, port not exposed

## Relationship to Known CVEs

| CVE | Attribute | Status in This Repo |
|-----|-----------|-------------------|
| CVE-2024-3596 | Proxy-State | PoC #1 — verified mitigation in modern FreeRADIUS |
| (none) | All others | Protocol-level design limitations of RFC 2865, not implementation bugs |

> **Note:** The remaining 11 cases exploit the **same root cause** — lack of integrity protection on Access-Request attributes in RFC 2865. This is a known protocol design limitation, not an implementation vulnerability. The recommended mitigation is Message-Authenticator (RFC 2869) or RadSec/RADIUS-over-TLS (RFC 6614).

## Attack Assumption Strength

| Strength | PoCs | Rationale |
|----------|------|-----------|
| **Weak (realistic)** | #6 CHAP | Passive sniffing only, no MITM needed |
| **Moderate** | #1, #2, #7, #9, #11 | On-path + common deployment patterns |
| **Strong (theoretical)** | #3, #5, #8, #10, #12 | Requires specific server policy configurations |
| **Mitigated** | #1, #4 | Modern FreeRADIUS defaults prevent these |

## Repository Structure

```
├── README.md
├── results/                          # Detailed threat models & attack procedures
│   ├── Access_Request_Proxy_State_response.txt
│   ├── Access_Request_Called_Station_Id_response.txt
│   ├── Access_Request_NAS_IPv6_Address_response.txt
│   ├── Access_Request_EAP_Message_response.txt
│   ├── Access_Request_Framed_Protocol_response.txt
│   ├── Access_Request_CHAP_Password_response.txt
│   ├── Access_Request_NAS_Port_Type_response.txt
│   ├── Access_Request_Tunnel_Type_response.txt
│   ├── Access_Request_Tunnel_Private_Group_Id_response.txt
│   ├── Access_Request_Tunnel_Server_Endpoint_response.txt
│   ├── CoA_Request_Tunnel_Private_Group_Id_response.txt
│   └── CoA_Request_Vendor_Specific_response.txt
├── poc/
│   ├── docker-compose.yml            # 3-container test environment
│   ├── scripts/
│   │   ├── radius_utils.py           # RADIUS packet construction library
│   │   ├── mitm_proxy.py             # Generic MITM proxy with rule engine
│   │   ├── e2e_framework.py          # NAS simulator + E2E test framework
│   │   ├── e2e_all_pocs.py           # All 12 PoCs end-to-end
│   │   └── b_results_verify.py       # Quick verification (direct send)
│   └── config/
│       ├── Dockerfile.freeradius
│       ├── Dockerfile.attacker
│       ├── clients.conf
│       ├── authorize                 # User/device policies
│       └── sites-default             # Attribute-based authorization rules
└── docs/
```

## Quick Start

```bash
# 1. Build and start the test environment
cd poc/
docker compose up -d --build

# 2. Wait for FreeRADIUS to be ready
docker compose logs freeradius | tail -3
# Should show: "Ready to process requests"

# 3. Run all 12 PoCs end-to-end
docker compose exec attacker python /scripts/e2e_all_pocs.py

# 4. Or run quick verification (direct packet send)
docker compose exec attacker python /scripts/b_results_verify.py
```

## Mitigations

| Mitigation | Protects Against | Deployment Effort |
|------------|-----------------|-------------------|
| **Message-Authenticator** (RFC 2869) | MITM attribute tampering on Access-Request | Low — enable on NAS and server |
| **RadSec / RADIUS-over-TLS** (RFC 6614) | All on-path attacks | Medium — requires TLS infrastructure |
| **Strong passwords + EAP-TLS** | CHAP offline cracking | Medium — requires PKI |
| **Server-side policy hardening** | Attribute hint abuse | Low — don't trust request hints for authorization |
| **Upgrade FreeRADIUS ≥ 3.2.3** | CVE-2024-3596 (Blast-RADIUS) | Low |

## References

- [RFC 2865 — Remote Authentication Dial In User Service (RADIUS)](https://datatracker.ietf.org/doc/html/rfc2865)
- [RFC 2868 — RADIUS Attributes for Tunnel Protocol Support](https://datatracker.ietf.org/doc/html/rfc2868)
- [RFC 3579 — RADIUS Support for EAP](https://datatracker.ietf.org/doc/html/rfc3579)
- [CVE-2024-3596 — Blast-RADIUS](https://www.blastradius.fail/)
- [RFC 6614 — Transport Layer Security (TLS) Encryption for RADIUS](https://datatracker.ietf.org/doc/html/rfc6614)

## Disclaimer

This repository is for **educational and authorized security research purposes only**. The PoC scripts are designed to run in an isolated Docker environment. Do not use these tools against systems you do not own or have explicit authorization to test.
