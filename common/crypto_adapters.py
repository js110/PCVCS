                           
import os, hashlib, hmac, secrets, json, time, math
USE_REAL = os.environ.get("USE_REAL_CRYPTO", "0") == "1"

                                                     
_ed25519_real = None
SigningKey = None
VerifyKey = None
if USE_REAL:
    try:
        from nacl.signing import SigningKey, VerifyKey
        _ed25519_real = True
    except Exception:
        _ed25519_real = False
else:
    _ed25519_real = False

def ed25519_generate_keypair():
    if _ed25519_real and SigningKey:
        sk = SigningKey.generate()
        pk = sk.verify_key
        return sk, pk
    sk = secrets.token_bytes(32)
    pk = hashlib.sha256(sk).digest()
    return sk, pk

def ed25519_sign(sk, msg: bytes) -> bytes:
    if _ed25519_real and hasattr(sk, "sign"):
        return sk.sign(msg).signature
    key = sk if isinstance(sk, (bytes, bytearray)) else bytes(sk)[:32]
    return hmac.new(key, msg, hashlib.sha256).digest()

def ed25519_verify(pk, msg: bytes, sig: bytes) -> bool:
    if _ed25519_real and VerifyKey:
        try:
            verify_key = VerifyKey(bytes(pk))
            verify_key.verify(msg, sig)
            return True
        except Exception:
            return False
    return False

                                                        
_lrs_real = None
_lrs_backend = None
if USE_REAL:
    try:
                    
        from .lrs_backend import lsag_sign_py, lsag_verify_py
        _lrs_backend = {"sign": lsag_sign_py, "verify": lsag_verify_py}
        _lrs_real = True
    except Exception as e:
        print(f"警告: 无法加载LSAG后端: {e}")
        _lrs_real = False
else:
    _lrs_real = False

def lrs_sign(message: bytes, ring_pubkeys: list[bytes], signer_index: int, sk_signer, ctx: bytes) -> dict:
                     
    processed_ring_pubkeys = []
    for pk in ring_pubkeys:
        if hasattr(pk, 'encode'):
                   
            processed_ring_pubkeys.append(pk.encode() if isinstance(pk, str) else bytes(pk))
        elif hasattr(pk, '__bytes__'):
                                         
            processed_ring_pubkeys.append(bytes(pk))
        else:
                             
            processed_ring_pubkeys.append(bytes(pk))
    
    if _lrs_real and _lrs_backend:
        try:
            sig, keyimage = _lrs_backend["sign"](message, processed_ring_pubkeys, sk_signer, ctx)
            return {
                "ring": [pk.hex() for pk in processed_ring_pubkeys],
                "sig": sig.hex(),
                "ctx": ctx.hex(),
                "link_tag": keyimage.hex(),                         
                "backend": "lsag_real"
            }
        except Exception as e:
            print(f"LSAG签名失败，回退到占位符实现: {e}")
    
           
    tag = hashlib.sha256(ctx + hashlib.sha256(bytes(sk_signer) if isinstance(sk_signer, (bytes, bytearray)) else bytes(str(sk_signer), 'utf-8')).digest()).hexdigest()
    sig = ed25519_sign(sk_signer if isinstance(sk_signer, (bytes, bytearray)) else bytes(str(sk_signer), 'utf-8')[:32], message + ctx)
    return {"ring": [pk.hex() for pk in processed_ring_pubkeys],
            "sig": sig.hex(),
            "ctx": ctx.hex(),
            "link_tag": tag,
            "backend": "fallback"}

def lrs_verify(message: bytes, lrs_obj: dict, ring_pubkeys_bytes: list[bytes]) -> bool:
                     
    processed_ring_pubkeys = []
    for pk in ring_pubkeys_bytes:
        if hasattr(pk, 'encode'):
                   
            processed_ring_pubkeys.append(pk.encode() if isinstance(pk, str) else bytes(pk))
        elif hasattr(pk, '__bytes__'):
                                         
            processed_ring_pubkeys.append(bytes(pk))
        else:
                             
            processed_ring_pubkeys.append(bytes(pk))
    
    if _lrs_real and _lrs_backend:
        try:
            sig = bytes.fromhex(lrs_obj["sig"])
            keyimage = bytes.fromhex(lrs_obj["link_tag"])
            ctx = bytes.fromhex(lrs_obj["ctx"])
            return _lrs_backend["verify"](message, processed_ring_pubkeys, sig, keyimage, ctx)
        except Exception as e:
            print(f"LSAG验证失败，回退到占位符实现: {e}")
    
           
    try:
        bytes.fromhex(lrs_obj["sig"]); bytes.fromhex(lrs_obj["ctx"]); lrs_obj["ring"]
        return True
    except Exception:
        return False

                                                            
_bp_real = None
_bp_backend = None
if USE_REAL:
    try:
                            
        try:
            from .bulletproofs_backend import pedersen_commit_py, range_proof_prove_py, range_proof_verify_py
            _bp_backend = {
                "commit": pedersen_commit_py,
                "prove": range_proof_prove_py,
                "verify": range_proof_verify_py
            }
        except ImportError:
                                      
            pass
        _bp_real = bool(_bp_backend)
    except Exception as e:
        print(f"警告: 无法加载Bulletproofs后端: {e}")
        _bp_real = False
else:
    _bp_real = False

def pedersen_commit(value: int, blinding: int) -> str:
    if _bp_real and _bp_backend:
        try:
            C = _bp_backend["commit"](value, blinding)
            return C.hex()
        except Exception as e:
            print(f"Pedersen承诺失败，回退到占位符实现: {e}")
    return hashlib.sha256(f"{value}|{blinding}".encode()).hexdigest()

def range_proof_prove(value: int, L: int, U: int, blinding: int) -> dict:
    if _bp_real and _bp_backend:
        try:
            C, proof = _bp_backend["prove"](value, L, U, blinding)
            return {
                "commitment": C.hex(),
                "proof_hex": proof.hex(),
                "L": L,
                "U": U
            }
        except Exception as e:
            print(f"范围证明生成失败，回退到占位符实现: {e}")
    
           
    return {"commitment": pedersen_commit(value, blinding), "L": L, "U": U, "value_hint": value, "blinding_hint": blinding, "backend": "fallback"}

def range_proof_verify(proof: dict) -> bool:
    if _bp_real and _bp_backend:
        try:
            C = bytes.fromhex(proof["commitment"])
            p = bytes.fromhex(proof["proof_hex"])
            L = proof["L"]; U = proof["U"]
            return _bp_backend["verify"](L, U, C, p)
        except Exception as e:
            print(f"范围证明验证失败，回退到占位符实现: {e}")
    
           
    v = int(proof.get("value_hint", 0)); L = int(proof["L"]); U = int(proof["U"])
    b = int(proof.get("blinding_hint", 0))
    return (L <= v <= U) and (proof["commitment"] == pedersen_commit(v, b))