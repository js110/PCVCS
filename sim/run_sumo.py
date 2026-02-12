
                 
                                                                                                 
                                                                                     

import os, json, time, random, math, argparse
from pathlib import Path
from datetime import datetime, timedelta
from common.crypto import ed25519_generate_keypair, ed25519_sign, geohash_encode

def synthetic_sim(num_rsus=3, num_events=200, window_len=60, token_expiry=3600, region_id="ROAD_SEG_A"):
                     
    rsus = []
    for i in range(num_rsus):
        sk, pk = ed25519_generate_keypair()
        rsus.append({"rsu_id": i+1, "sk": sk, "pk": pk})
                                
    now = int(time.time())
    events = []
    for e in range(num_events):
        rsu = random.choice(rsus)
        window_id = (e % 1000) + 1
        nonce = random.getrandbits(64)
                     
        expiry = now + token_expiry
        msg = f"{1}|{region_id}|{window_id}|{nonce}|{expiry}|{rsu['rsu_id']}".encode()
        sig = ed25519_sign(rsu["sk"], msg)
        token = {
            "version": 1,
            "region_id": region_id,
            "window_id": window_id,
            "nonce": nonce,
            "expiry_ts": expiry,
            "rsu_id": rsu["rsu_id"],
            "signature_hex": sig.hex()
        }
                                                                                    
        lat = 31.23 + random.uniform(-0.01, 0.01)
        lon = 121.47 + random.uniform(-0.01, 0.01)
        g7 = geohash_encode(lat, lon, precision=7)
        events.append({"token": token, "lat": lat, "lon": lon, "geohash7": g7, "timestamp": now})
        now += random.randint(1, 5)
    return rsus, events

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=str, default=str(Path(__file__).parent.parent / "data" / "rsu_events.json"))
    ap.add_argument("--token-expiry", type=int, default=3600, help="token expiry time in seconds (default: 3600s = 1 hour)")
    args = ap.parse_args()
    rsus, events = synthetic_sim(token_expiry=args.token_expiry)
    out = Path(args.out)
    out.write_text(json.dumps({"rsus": [{"rsu_id": r["rsu_id"], "pk_hex": r["pk"].hex()} for r in rsus],
                               "events": events}, ensure_ascii=False, indent=2))
    print(f"[OK] Synthetic RSU events saved -> {out}")

if __name__ == "__main__":
    main()