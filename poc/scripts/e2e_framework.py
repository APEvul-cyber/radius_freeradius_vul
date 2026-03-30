#!/usr/bin/env python3
"""
RADIUS 端到端攻击验证框架
===========================
完整链路: NAS → MITM Proxy → FreeRADIUS Server → MITM Proxy → NAS

NAS 模拟器:
  - 构造原始（未篡改）Access-Request
  - 验证 Response Authenticator（用 shared secret）
  - 解析并"应用"授权属性

验证流程:
  1. NAS 直连 Server（基线，无攻击）
  2. NAS 经 MITM 连 Server（MITM 篡改属性）
  3. 对比两次授权结果差异
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

MITM_PORT = 1814  # MITM 代理监听端口（本地）


# ============================================================
# NAS 模拟器
# ============================================================
class NASSimulator:
    """模拟真实 NAS 行为"""

    def __init__(self, secret=SHARED_SECRET):
        self.secret = secret
        self.last_request_auth = None
        self.last_response = None
        self.applied_policy = {}

    def send_access_request(self, attrs_bytes, server="172.20.0.10",
                            port=RADIUS_AUTH_PORT, identifier=0x5A):
        """发送 Access-Request 并验证响应"""
        auth = compute_request_authenticator()
        self.last_request_auth = auth

        packet = build_radius_packet(CODE_ACCESS_REQUEST, identifier, auth, attrs_bytes)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)
        try:
            sock.sendto(packet, (server, port))
            resp_data, _ = sock.recvfrom(4096)
        except Exception as e:
            self.last_response = {"code": -1, "code_name": "Error", "error": str(e), "attributes": []}
            self.applied_policy = {"error": str(e)}
            return self.last_response
        finally:
            sock.close()

        resp = parse_radius_response(resp_data)
        self.last_response = resp

        # 验证 Response Authenticator
        resp_code = resp_data[0]
        resp_id = resp_data[1]
        resp_len = struct.unpack("!H", resp_data[2:4])[0]
        resp_auth_received = resp_data[4:20]
        resp_attrs = resp_data[20:resp_len]

        expected_auth = hashlib.md5(
            struct.pack("!BBH", resp_code, resp_id, resp_len) +
            auth + resp_attrs + self.secret
        ).digest()

        resp["auth_valid"] = (resp_auth_received == expected_auth)

        # 应用授权（模拟 NAS 行为）
        self.applied_policy = self._extract_policy(resp)
        resp["applied_policy"] = self.applied_policy

        return resp

    def _extract_policy(self, resp):
        """从 Access-Accept 中提取授权策略"""
        policy = {}
        if resp.get("code") != CODE_ACCESS_ACCEPT:
            policy["access"] = "DENIED"
            return policy

        policy["access"] = "GRANTED"
        for attr in resp.get("attributes", []):
            t = attr["type"]
            v = attr.get("value", attr.get("raw_value"))
            if t == ATTR_REPLY_MESSAGE:
                policy["reply_message"] = v
            elif t == 11:  # Filter-Id
                policy["filter_id"] = v
            elif t == ATTR_TUNNEL_PRIVATE_GROUP_ID:
                policy["tunnel_group"] = v
            elif t == ATTR_TUNNEL_TYPE:
                policy["tunnel_type"] = v
            elif t == ATTR_TUNNEL_MEDIUM_TYPE:
                policy["tunnel_medium"] = v
            elif t == 67:  # Tunnel-Server-Endpoint
                policy["tunnel_endpoint"] = v
            elif t == ATTR_SERVICE_TYPE:
                policy["service_type"] = v
        return policy

    def build_pap_attrs(self, username, password, extra_attrs=None):
        """构造 PAP 认证属性"""
        auth = compute_request_authenticator()
        self.last_request_auth = auth
        attrs = b""
        attrs += build_string_attr(ATTR_USER_NAME, username)
        attrs += build_attribute(ATTR_USER_PASSWORD,
                                 encode_password(password.encode(), self.secret, auth))
        attrs += build_ipaddr_attr(ATTR_NAS_IP_ADDRESS, "10.0.0.1")
        if extra_attrs:
            attrs += extra_attrs
        return attrs, auth


# ============================================================
# 端到端测试框架
# ============================================================
class E2ETestRunner:
    """端到端攻击验证"""

    def __init__(self):
        self.nas = NASSimulator()
        self.proxy = MITMProxy(listen_port=MITM_PORT)
        self.results = []

    def start_proxy(self):
        self.proxy.start_background()

    def stop_proxy(self):
        self.proxy.stop()

    def run_test(self, name, classification, build_attrs_fn, mitm_rules,
                 check_fn, extra_attrs_baseline=None):
        """
        运行单个端到端测试:
        1. NAS 直连 Server（基线）
        2. NAS 经 MITM 连 Server（攻击）
        3. check_fn 判断攻击是否成功
        """
        print(f"\n{'=' * 60}")
        print(f"  {name}")
        print(f"{'=' * 60}")

        # --- 基线：NAS 直连 Server ---
        print("  [1] NAS → Server（直连，无攻击）")
        attrs_baseline, auth_b = build_attrs_fn(attack=False)
        # 需要用 auth 来加密密码，所以直接构造完整包
        resp_baseline = self._send_via_nas(attrs_baseline, auth_b, "172.20.0.10", RADIUS_AUTH_PORT, 0x40)
        policy_baseline = resp_baseline.get("applied_policy", {})
        auth_valid_b = resp_baseline.get("auth_valid", False)
        print(f"       响应: {resp_baseline.get('code_name')}, Auth验证: {'✓' if auth_valid_b else '✗'}")
        print(f"       策略: {policy_baseline}")

        # --- 攻击：NAS → MITM → Server ---
        print("  [2] NAS → MITM → Server（MITM 篡改属性）")
        self.proxy.clear_rules()
        for rule in mitm_rules:
            self.proxy.add_rule(rule)

        attrs_attack, auth_a = build_attrs_fn(attack=False)  # NAS 发的是原始包
        resp_attack = self._send_via_nas(attrs_attack, auth_a, "127.0.0.1", MITM_PORT, 0x41)
        policy_attack = resp_attack.get("applied_policy", {})
        auth_valid_a = resp_attack.get("auth_valid", False)
        print(f"       响应: {resp_attack.get('code_name')}, Auth验证: {'✓' if auth_valid_a else '✗'}")
        print(f"       策略: {policy_attack}")

        # MITM 日志
        if self.proxy.log:
            last = self.proxy.log[-1]
            print(f"       MITM 操作: {last.get('actions', [])}")

        # --- 判断攻击结果 ---
        result = check_fn(resp_baseline, resp_attack, policy_baseline, policy_attack)
        success = result["success"]
        detail = result["detail"]

        status = "✓ ATTACK SUCCESS" if success else "✗ ATTACK FAILED"
        print(f"\n  [{status}]")
        print(f"    NAS Auth 验证: 基线={'✓' if auth_valid_b else '✗'}, 攻击={'✓' if auth_valid_a else '✗'}")
        print(f"    {detail}")

        self.results.append({
            "name": name,
            "classification": classification,
            "success": success,
            "detail": detail,
            "auth_valid_baseline": auth_valid_b,
            "auth_valid_attack": auth_valid_a,
        })

    def _send_via_nas(self, attrs, auth, server, port, identifier):
        """通过 NAS 模拟器发送请求"""
        packet = build_radius_packet(CODE_ACCESS_REQUEST, identifier, auth, attrs)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)
        try:
            sock.sendto(packet, (server, port))
            resp_data, _ = sock.recvfrom(4096)
        except Exception as e:
            return {"code": -1, "code_name": "Error", "error": str(e),
                    "attributes": [], "auth_valid": False, "applied_policy": {"error": str(e)}}
        finally:
            sock.close()

        resp = parse_radius_response(resp_data)

        # 验证 Response Authenticator
        resp_code = resp_data[0]
        resp_id = resp_data[1]
        resp_len = struct.unpack("!H", resp_data[2:4])[0]
        resp_auth_received = resp_data[4:20]
        resp_attrs_raw = resp_data[20:resp_len]

        expected = hashlib.md5(
            struct.pack("!BBH", resp_code, resp_id, resp_len) +
            auth + resp_attrs_raw + SHARED_SECRET
        ).digest()
        resp["auth_valid"] = (resp_auth_received == expected)

        # 提取策略
        policy = {"access": "GRANTED" if resp.get("code") == CODE_ACCESS_ACCEPT else "DENIED"}
        for attr in resp.get("attributes", []):
            t = attr["type"]
            v = attr.get("value", attr.get("raw_value"))
            if t == ATTR_REPLY_MESSAGE:
                policy["reply_message"] = v
            elif t == 11:
                policy["filter_id"] = v
            elif t == ATTR_TUNNEL_PRIVATE_GROUP_ID:
                policy["tunnel_group"] = v
            elif t == ATTR_TUNNEL_TYPE:
                policy["tunnel_type"] = v
            elif t == 67:
                policy["tunnel_endpoint"] = v
            elif t == ATTR_SERVICE_TYPE:
                policy["service_type"] = v
        resp["applied_policy"] = policy
        return resp

    def print_summary(self):
        print(f"\n\n{'#' * 60}")
        print(f"#  端到端攻击验证结果汇总")
        print(f"{'#' * 60}")
        passed = sum(1 for r in self.results if r["success"])
        total = len(self.results)
        print(f"\n  攻击成功: {passed}/{total}\n")
        for r in self.results:
            s = "✓" if r["success"] else "✗"
            auth = "Auth✓" if r["auth_valid_attack"] else "Auth✗"
            print(f"  {s} [{auth}] {r['name']}")
            print(f"          {r['detail']}")
        print(f"\n{'#' * 60}\n")
