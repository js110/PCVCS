
# common/crypto.py
# DISCLAIMER:
# This is a **stub** crypto layer for reproducibility without external deps.
# Replace with real libs in production:
# - Ed25519 signatures (pynacl/libsodium)
# - LRS/LSAG ring signatures
# - Bulletproofs range proofs (bindings)
# - Kyber/ML-KEM for session keys
#
# Here we use HMAC-SHA256 as a placeholder "signature" and "verification".
# DO NOT use in production.

import hmac, hashlib, secrets, time, json, math, random

def now_s():
    return int(time.time())

# ---- "Ed25519" placeholder via HMAC (demo only) ----
def ed25519_generate_keypair():
    sk = secrets.token_bytes(32)
    pk = hashlib.sha256(sk).digest()
    return sk, pk

def ed25519_sign(sk: bytes, msg: bytes) -> bytes:
    return hmac.new(sk, msg, hashlib.sha256).digest()

def ed25519_verify(pk: bytes, msg: bytes, sig: bytes, sk_hint: bytes=None) -> bool:
    # Demo verifier can't verify with pk; we allow passing sk_hint in demo.
    # In real impl: verify with pk. Here we simulate by checking against a registry.
    if sk_hint is None:
        # Best-effort: can't verify without secret; accept if pk==sha256(sk_hint)
        return False
    expected = hmac.new(sk_hint, msg, hashlib.sha256).digest()
    return hmac.compare_digest(expected, sig)

# ---- "LRS/LSAG" placeholder ----
# We simulate linkable ring signature by signing with one member's secret
# and deriving a link-tag as H(pk||ctx). This is NOT secure. Demo only.
def lrs_sign(message: bytes, ring_pubkeys: list[bytes], signer_index: int, sk_signer: bytes, ctx: bytes) -> dict:
    tag = hashlib.sha256(ctx + hashlib.sha256(sk_signer).digest()).hexdigest()
    sig = ed25519_sign(sk_signer, message + ctx)
    return {
        "ring": [pk.hex() for pk in ring_pubkeys],
        "sig": sig.hex(),
        "ctx": ctx.hex(),
        "link_tag": tag,
        "signer_index_demo": signer_index,  # demo only
    }

def lrs_verify(message: bytes, lrs_obj: dict, pk_registry: dict[str, bytes], sk_hint_registry: dict[str, bytes]) -> bool:
    try:
        ring_hex = lrs_obj["ring"]
        sig = bytes.fromhex(lrs_obj["sig"])
        ctx = bytes.fromhex(lrs_obj["ctx"])
        # Demo: accept if any member in ring has sk and verifies HMAC
        for pk_hex in ring_hex:
            pk = bytes.fromhex(pk_hex)
            sk = sk_hint_registry.get(pk_hex)
            if sk is None: 
                continue
            if ed25519_verify(pk, message + ctx, sig, sk_hint=sk):
                return True
        return False
    except Exception:
        return False

# ---- "Bulletproofs" placeholder ----
# We simulate a range proof as a dict with (commitment, range, opened_value)
# and verify by checking value in [L,U] and commitment hashes.
def pedersen_commit(value: int, blinding: int) -> str:
    # Demo commitment as sha256(str(v)||str(r))
    return hashlib.sha256(f"{value}|{blinding}".encode()).hexdigest()

def range_proof_prove(value: int, L: int, U: int, blinding: int) -> dict:
    c = pedersen_commit(value, blinding)
    return {"commitment": c, "L": L, "U": U, "value_demo": value, "blinding_demo": blinding}

def range_proof_verify(proof: dict) -> bool:
    v = int(proof["value_demo"])
    L = int(proof["L"]); U = int(proof["U"])
    c = proof["commitment"]
    b = int(proof["blinding_demo"])
    ok = (L <= v <= U) and (c == pedersen_commit(v, b))
    return ok

# ---- Simple Merkle (SHA256) ----
def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return ""
    nodes = [hashlib.sha256(x.encode()).digest() for x in leaves]
    while len(nodes) > 1:
        nxt = []
        for i in range(0, len(nodes), 2):
            a = nodes[i]
            b = nodes[i+1] if i+1 < len(nodes) else a
            nxt.append(hashlib.sha256(a + b).digest())
        nodes = nxt
    return nodes[0].hex()

def merkle_proof(leaves: list[str], index: int) -> list[str]:
    # Returns sibling hashes (hex)
    if not leaves: return []
    nodes = [hashlib.sha256(x.encode()).digest() for x in leaves]
    idx = index
    proof = []
    level = nodes[:]
    while len(level) > 1:
        if idx % 2 == 0:
            sib_idx = idx+1 if idx+1 < len(level) else idx
        else:
            sib_idx = idx-1
        proof.append(level[sib_idx].hex())
        # build next level
        nxt = []
        for i in range(0, len(level), 2):
            a = level[i]
            b = level[i+1] if i+1 < len(level) else a
            nxt.append(hashlib.sha256(a + b).digest())
        level = nxt
        idx //= 2
    return proof

def merkle_verify(leaf: str, proof: list[str], root_hex: str, index: int) -> bool:
    h = hashlib.sha256(leaf.encode()).digest()
    idx = index
    cur = h
    for sib_hex in proof:
        sib = bytes.fromhex(sib_hex)
        if idx % 2 == 0:
            cur = hashlib.sha256(cur + sib).digest()
        else:
            cur = hashlib.sha256(sib + cur).digest()
        idx //= 2
    return cur.hex() == root_hex

# ---- Geohash (basic) ----
_base32 = "0123456789bcdefghjkmnpqrstuvwxyz"

def geohash_encode(lat, lon, precision=7):
    # simplified geohash encoder
    lat_interval = [-90.0, 90.0]
    lon_interval = [-180.0, 180.0]
    bits = [16,8,4,2,1]
    bit = 0; ch = 0; even = True
    geostr = []
    while len(geostr) < precision:
        if even:
            mid = sum(lon_interval)/2
            if lon > mid:
                ch |= bits[bit]
                lon_interval[0] = mid
            else:
                lon_interval[1] = mid
        else:
            mid = sum(lat_interval)/2
            if lat > mid:
                ch |= bits[bit]
                lat_interval[0] = mid
            else:
                lat_interval[1] = mid
        even = not even
        if bit < 4:
            bit += 1
        else:
            geostr.append(_base32[ch])
            bit = 0; ch = 0
    return "".join(geostr)

# ---- Haversine distance ----
def haversine(lat1, lon1, lat2, lon2):
    R = 6371000.0
    phi1 = math.radians(lat1); phi2 = math.radians(lat2)
    dphi = math.radians(lat2-lat1); dl = math.radians(lon2-lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dl/2)**2
    c = 2*math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R*c

# ---- Token generation and verification ----

def generate_token(rsu_id: str, timestamp: int, expiry: int) -> dict:
    """Generate a simple token for RSU authentication"""
    # In a real implementation, this would use proper cryptographic signatures
    # For this demo, we'll create a simple token structure
    token_data = {
        "rsu_id": rsu_id,
        "timestamp": timestamp,
        "expiry": expiry,
        "nonce": secrets.token_hex(8)
    }
    return token_data

def verify_token(token: dict, rsu_id: str, current_timestamp: int) -> bool:
    """Verify a token's validity"""
    # Check if token is for the correct RSU
    if token.get("rsu_id") != rsu_id:
        return False
    
    # Check if token has expired
    if current_timestamp > token.get("timestamp", 0) + token.get("expiry", 0):
        return False
    
    # In a real implementation, we would also verify a cryptographic signature
    # For this demo, we'll assume the token structure is valid if it has the required fields
    return "rsu_id" in token and "timestamp" in token and "expiry" in token

# ---- Simple geohash center (approx) ----
def geohash_bbox(geostr):
    # approximate bbox by iterative intervals
    lat_interval = [-90.0, 90.0]
    lon_interval = [-180.0, 180.0]
    bits = [16,8,4,2,1]
    even = True
    for ch in geostr:
        cd = _base32.index(ch)
        for mask in bits:
            if even:
                if cd & mask:
                    lon_interval[0] = sum(lon_interval)/2
                else:
                    lon_interval[1] = sum(lon_interval)/2
            else:
                if cd & mask:
                    lat_interval[0] = sum(lat_interval)/2
                else:
                    lat_interval[1] = sum(lat_interval)/2
            even = not even
    lat = sum(lat_interval)/2; lon = sum(lon_interval)/2
    return lat, lon

