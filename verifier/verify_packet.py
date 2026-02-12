                      
                       

                           
                                                                                                    
                                                            

import json, time, argparse
from pathlib import Path
from common.crypto import (
    geohash_encode, geohash_bbox, pedersen_commit, range_proof_verify,
    ed25519_verify, merkle_verify, now_s, haversine
)
from common.crypto_adapters import ed25519_generate_keypair, range_proof_verify as adapter_range_proof_verify, lrs_verify

                                                                             
                                                        
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
    speed = d/dt              
    limit = 50*1000/3600                  
    tol = 150                    
    if speed > limit + tol/dt:
        return False, f"ERR_SPEED_LIMIT_EXCEEDED (v={speed:.1f} m/s, limit={limit:.1f} m/s)"
    return True, f"OK (v={speed:.1f} m/s)"

def verify_token_freshness(packet, max_age=3600) -> tuple[bool, str]:          
    now = now_s()
    expiry = packet["token"]["expiry_ts"]
    if expiry < now:
        return False, "ERR_TOKEN_EXPIRED"
    age = now - packet["timestamp"]
    if age > max_age:
        return False, f"ERR_TOKEN_TOO_OLD (age={age}s)"
    return True, f"OK (age={age}s)"

def verify_packet(packet, ctx="window-ctx-001") -> tuple[bool, str]:
                                   
    ok, msg = verify_token_freshness(packet)
    if not ok: return False, f"token: {msg}"

                                                          
    root = bytes.fromhex(packet["tree_root"])
    leaf = packet["geohash7"]
    proof = packet["audit_path"]
    idx = 0                  
    if not merkle_verify(leaf, proof, root.hex(), idx):
        return False, "ERR_MERKLE_PROOF_INVALID"
    
                                               
    for proof_dict in packet["proofs"]:
                                                 
        if not adapter_range_proof_verify(proof_dict):
            return False, "ERR_RANGE_PROOF_INVALID"
    
                                         
               
    message = json.dumps({
        "payload": packet["payload"],
        "geohash7": packet["geohash7"],
        "timestamp": packet["timestamp"],
        "token": packet["token"]
    }, separators=(",", ":")).encode()
    
    lrs_obj = packet["lrs"]
             
    ring_pubkeys_bytes = [bytes.fromhex(pk_hex) for pk_hex in lrs_obj["ring"]]
    
                                     
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
    
                                                     
                          
    if "ring_sk_hint" in obj:
        ring_sks = obj["ring_sk_hint"]
        ring_pks = packet["lrs"]["ring"]
        for sk_hex, pk_dict in zip(ring_sks, ring_pks):
            pk_hex = pk_dict["pk_hex"]
            SK_HINT_REGISTRY[pk_hex] = bytes.fromhex(sk_hex)
    else:
                                        
        if "rsus" in obj and len(obj["rsus"]) > 0:
            for rsu in obj["rsus"]:
                pk_hex = rsu["pk_hex"]
                sk_hex = rsu["sk_hex"]
                SK_HINT_REGISTRY[pk_hex] = bytes.fromhex(sk_hex)
        else:
                                
            for i in range(8):
                sk, pk = ed25519_generate_keypair()
                pk_hex = pk.hex() if isinstance(pk, bytes) else bytes(pk).hex()
                sk_hex = sk.hex() if isinstance(sk, bytes) else bytes(sk).hex()
                SK_HINT_REGISTRY[pk_hex] = bytes.fromhex(sk_hex)

                         
    original_verify_token_freshness = None
    if args.skip_expiry:
                  
        original_verify_token_freshness = globals()['verify_token_freshness']
        
                         
        def skip_expiry_verify_token_freshness(packet, max_age=3600):
            return True, "OK (expiry check skipped)"
        
                  
        globals()['verify_token_freshness'] = skip_expiry_verify_token_freshness

    ok, msg = verify_packet(packet, ctx=args.ctx)
    
              
    if args.skip_expiry and original_verify_token_freshness:
        globals()['verify_token_freshness'] = original_verify_token_freshness
        
    print(f"Verify: {ok}, {msg}")

if __name__ == "__main__":
    main()