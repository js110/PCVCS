#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# verifier/verify_packet.py
# Verify a demo packet: commitments + "range proofs" + "merkle member proof" + LRS stub + RSU token.
# Replace placeholders with real crypto libs for production.

import json, time, argparse
from pathlib import Path
from common.crypto import (
    geohash_encode, geohash_bbox, pedersen_commit, range_proof_verify,
    ed25519_verify, merkle_verify, now_s, haversine
)
from common.crypto_adapters import ed25519_generate_keypair, range_proof_verify as adapter_range_proof_verify, lrs_verify

# Demo verifier needs secret keys to simulate verification (not in real impl)
# We pass them via a registry mapping pk_hex -> sk_bytes
SK_HINT_REGISTRY = {}

def verify_speed_limit(packet, prev_report=None) -> tuple[bool, str]:
    if not prev_report:
        return True, "skip speed limit check (no prev)"
    lat1 = packet["payload"]["sensors"]["gps"]["lat"]
    lon1 = packet["payload"]["sensors"]["gps"]["lon"]
    t1 = packet["timestamp"]
    lat2 = prev_report["payload"]["sensors"]["gps"]["lat"]
    lon2 = prev_report["payload"]["sensors"]["gps"]["lon"]
    t2 = prev_report["timestamp"]
    d = haversine(lat1, lon1, lat2, lon2)
    dt = abs(t1-t2)
    if dt == 0: return True, "skip (t=0)"
    speed = d/dt  # meters/sec
    limit = 50*1000/3600  # 50 km/h in m/s
    tol = 150  # meters tolerance
    if speed > limit + tol/dt:
        return False, f"ERR_SPEED_LIMIT_EXCEEDED (v={speed:.1f} m/s, limit={limit:.1f} m/s)"
    return True, f"OK (v={speed:.1f} m/s)"

def verify_token_freshness(packet, max_age=3600) -> tuple[bool, str]:  # 增加到1小时
    now = now_s()
    expiry = packet["token"]["expiry_ts"]
    if expiry < now:
        return False, "ERR_TOKEN_EXPIRED"
    age = now - packet["timestamp"]
    if age > max_age:
        return False, f"ERR_TOKEN_TOO_OLD (age={age}s)"
    return True, f"OK (age={age}s)"

def verify_packet(packet, ctx="window-ctx-001") -> tuple[bool, str]:
    # 1. Verify RSU token freshness
    ok, msg = verify_token_freshness(packet)
    if not ok: return False, f"token: {msg}"

    # 2. Verify geohash is in whitelist (via Merkle proof)
    root = bytes.fromhex(packet["tree_root"])
    leaf = packet["geohash7"]
    proof = packet["audit_path"]
    idx = 0  # 在实际实现中需要正确计算索引
    if not merkle_verify(leaf, proof, root.hex(), idx):
        return False, "ERR_MERKLE_PROOF_INVALID"
    
    # 3. Verify range proof (stub Bulletproofs)
    for proof_dict in packet["proofs"]:
        # 使用crypto_adapters中的range_proof_verify函数
        if not adapter_range_proof_verify(proof_dict):
            return False, "ERR_RANGE_PROOF_INVALID"
    
    # 4. Verify LRS ring signature (stub)
    # 构造用于验证的消息
    message = json.dumps({
        "payload": packet["payload"],
        "geohash7": packet["geohash7"],
        "timestamp": packet["timestamp"],
        "token": packet["token"]
    }, separators=(",", ":")).encode()
    
    lrs_obj = packet["lrs"]
    # 构造环公钥列表
    ring_pubkeys_bytes = [bytes.fromhex(pk_hex) for pk_hex in lrs_obj["ring"]]
    
    # 使用crypto_adapters中的lrs_verify函数
    result = lrs_verify(message, lrs_obj, ring_pubkeys_bytes)
    
    if not result:
        return False, "ERR_LRS_VERIFY_FAIL"
    
    return True, "OK"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--infile", type=str, default=str(Path(__file__).parent.parent / "data" / "packet.json"))
    ap.add_argument("--ctx", type=str, default="window-ctx-001")
    ap.add_argument("--skip-expiry", action="store_true", help="Skip token expiry check for testing")
    args = ap.parse_args()

    obj = json.loads(Path(args.infile).read_text())
    packet = obj["packet"]
    
    # Populate SK hint registry for demo verification
    # 检查是否存在ring_sk_demo字段
    if "ring_sk_demo" in obj:
        ring_sks = obj["ring_sk_demo"]
        ring_pks = packet["lrs"]["ring"]
        for sk_hex, pk_dict in zip(ring_sks, ring_pks):
            pk_hex = pk_dict["pk_hex"]
            SK_HINT_REGISTRY[pk_hex] = bytes.fromhex(sk_hex)
    else:
        # 如果没有ring_sk_demo字段，使用RSU中的私钥信息
        if "rsus" in obj and len(obj["rsus"]) > 0:
            for rsu in obj["rsus"]:
                pk_hex = rsu["pk_hex"]
                sk_hex = rsu["sk_hex"]
                SK_HINT_REGISTRY[pk_hex] = bytes.fromhex(sk_hex)
        else:
            # 如果都没有，生成一些示例密钥用于演示
            for i in range(8):
                sk, pk = ed25519_generate_keypair()
                pk_hex = pk.hex() if isinstance(pk, bytes) else bytes(pk).hex()
                sk_hex = sk.hex() if isinstance(sk, bytes) else bytes(sk).hex()
                SK_HINT_REGISTRY[pk_hex] = bytes.fromhex(sk_hex)

    # 如果设置了跳过过期检查，则修改验证函数
    original_verify_token_freshness = None
    if args.skip_expiry:
        # 保存原始验证函数
        original_verify_token_freshness = globals()['verify_token_freshness']
        
        # 创建新的验证函数，总是返回成功
        def skip_expiry_verify_token_freshness(packet, max_age=3600):
            return True, "OK (expiry check skipped)"
        
        # 临时替换验证函数
        globals()['verify_token_freshness'] = skip_expiry_verify_token_freshness

    ok, msg = verify_packet(packet, ctx=args.ctx)
    
    # 恢复原始验证函数
    if args.skip_expiry and original_verify_token_freshness:
        globals()['verify_token_freshness'] = original_verify_token_freshness
        
    print(f"Verify: {ok}, {msg}")

if __name__ == "__main__":
    main()