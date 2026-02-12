
import json, time, argparse
from pathlib import Path
from common.crypto import merkle_verify, geohash_bbox, haversine
from common.crypto_adapters import range_proof_verify, lrs_verify
from common.linkable_ring_signature import LinkableRingSignature, PublicKeyRing

USED_NONCES = set()
# 初始化全局LRS验证器（用于检测重复提交）
LRS_VERIFIER = LinkableRingSignature()

def verify_token(token: dict, skip_expiry: bool = False) -> tuple[bool, str]:
    now = int(time.time())
    if not skip_expiry and token["expiry_ts"] < now:
        return False, "ERR_TOKEN_EXPIRED"
    key = (token["window_id"], token["nonce"])
    if key in USED_NONCES:
        return False, "ERR_TOKEN_REPLAY"
    USED_NONCES.add(key)
    return True, "OK"

def verify_packet(packet_obj: dict, ctx: str, vmax_kmh: float = 50.0, last_report=None, skip_expiry: bool = False):
    # 1. 验证Token
    ok, msg = verify_token(packet_obj["token"], skip_expiry=skip_expiry)
    if not ok:
        return False, msg
    
    # 2. 验证时间范围证明（Bulletproofs）
    if not range_proof_verify(packet_obj["proofs"]["Pi_time"]):
        return False, "ERR_ZK_TIME"

    # 3. 验证Merkle地理证明
    root = packet_obj["commitments"]["root"]
    leaf = packet_obj["geohash7"]
    proof = packet_obj["proofs"]["Pi_geo"]["proof"]
    idx = packet_obj["proofs"]["Pi_geo"]["index"]
    if not merkle_verify(leaf, proof, root, idx):
        return False, "ERR_GEO_PROOF"

    # 4. 重构消息 M = (tid, Cm, Cg, Ct, Ctok)
    task_id = packet_obj.get("task_id", "unknown")
    message = json.dumps({
        "tid": task_id,
        "payload": packet_obj["payload"],
        "commitments": packet_obj["commitments"],
        "proofs": packet_obj["proofs"],
        "token": packet_obj["token"]
    }, separators=(",",":")).encode()

    # 5. 验证可关联环签名（σLRS）
    sigma_lrs = packet_obj.get("sigma_lrs", packet_obj.get("lrs", {}))  # 兼容旧格式
    
    # 重构公钥环 Rring
    ring_pubkeys_hex = packet_obj.get("ring_pubkeys", sigma_lrs.get("ring", []))
    ring_bytes = [bytes.fromhex(pk_hex) for pk_hex in ring_pubkeys_hex]
    
    # 创建公钥环对象
    public_ring = PublicKeyRing(
        ring_id=sigma_lrs.get("ring_id", "unknown"),
        task_id=task_id,
        registered_pubkeys=ring_bytes,
        creation_time=int(time.time())
    )
    
    # 验证LRS签名
    if not LRS_VERIFIER.verify_signature(message, sigma_lrs, public_ring):
        return False, "ERR_LRS_INVALID"
    
    # 6. 检测重复提交（通过link_tag）
    is_duplicate, previous = LRS_VERIFIER.detect_duplicate_submission(sigma_lrs, task_id)
    if is_duplicate:
        return False, f"ERR_DUPLICATE_SUBMISSION (link_tag={sigma_lrs['link_tag'][:16]}..., previous={len(previous)} submissions)"
    
    # 7. 速度一致性检查（可选）
    if last_report is not None:
        vmax = vmax_kmh * 1000.0 / 3600.0
        lat1, lon1 = geohash_bbox(last_report["geohash7"])
        lat2, lon2 = geohash_bbox(packet_obj["geohash7"])
        d = haversine(lat1, lon1, lat2, lon2)
        dt = packet_obj["timestamp"] - last_report["timestamp"]
        if dt <= 0:
            return False, "ERR_TIME_BACKWARD"
        if d > vmax * dt + 150.0:
            return False, "ERR_SPEED_VIOLATION"

    return True, "OK"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--infile", type=str, default=str(Path(__file__).parent.parent / "data" / "packet.json"))
    ap.add_argument("--ctx", type=str, default="window-ctx-001")
    ap.add_argument("--skip-expiry", action="store_true", help="跳过token过期检查（用于测试）")
    args = ap.parse_args()

    obj = json.loads(Path(args.infile).read_text())
    packet = obj["packet"]
    ok, msg = verify_packet(packet, ctx=args.ctx, skip_expiry=args.skip_expiry)
    print(f"Verify: {ok}, {msg}")

if __name__ == "__main__":
    main()
