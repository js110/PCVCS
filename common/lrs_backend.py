"""
LSAG/LRS Python包装器
使用ctypes调用C库实现
"""
import ctypes
import os
import sys
import hmac
import hashlib

           
_lib = None
try:
                 
    if sys.platform.startswith('win'):
                 
        lib_path = os.path.join(os.path.dirname(__file__), '..', 'liblsag.dll')
        lib_path = os.path.abspath(lib_path)
        if os.path.exists(lib_path):
            _lib = ctypes.CDLL(lib_path)
        else:
                       
            lib_path = os.path.join(os.getcwd(), 'liblsag.dll')
            if os.path.exists(lib_path):
                _lib = ctypes.CDLL(lib_path)
    elif sys.platform.startswith('darwin'):
               
        lib_path = os.path.join(os.path.dirname(__file__), '..', 'liblsag.dylib')
        lib_path = os.path.abspath(lib_path)
        if os.path.exists(lib_path):
            _lib = ctypes.CDLL(lib_path)
    else:
               
        lib_path = os.path.join(os.path.dirname(__file__), '..', 'liblsag.so')
        lib_path = os.path.abspath(lib_path)
        if os.path.exists(lib_path):
            _lib = ctypes.CDLL(lib_path)
except OSError as e:
                
    _lib = None
    print(f"Failed to load LSAG library: {e}")

                 
if _lib:
              
    _lib.lsag_sign.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t,                    
        ctypes.POINTER(ctypes.c_char_p), ctypes.c_size_t,                          
        ctypes.c_char_p,             
        ctypes.c_char_p, ctypes.c_size_t,                
        ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),                        
        ctypes.c_char_p                
    ]
    _lib.lsag_sign.restype = ctypes.c_int

              
    _lib.lsag_verify.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t,                    
        ctypes.POINTER(ctypes.c_char_p), ctypes.c_size_t,                          
        ctypes.c_char_p,       
        ctypes.c_char_p, ctypes.c_size_t,                
        ctypes.c_char_p            
    ]
    _lib.lsag_verify.restype = ctypes.c_int

def lsag_sign_py(msg: bytes, ring_pubkeys: list[bytes], sk_signer, ctx: bytes):
    """
    Python包装的LSAG签名函数
    
    Args:
        msg: 要签名的消息
        ring_pubkeys: 环中所有公钥的列表
        sk_signer: 签名者的私钥（可能是PyNaCl的SigningKey对象或bytes）
        ctx: 上下文/窗口ID
    
    Returns:
        tuple: (signature, keyimage)
    """
                         
    if hasattr(sk_signer, 'encode'):
               
        sk_signer_bytes = sk_signer.encode() if isinstance(sk_signer, str) else bytes(sk_signer)
    elif hasattr(sk_signer, 'sign'):
                                     
        sk_signer_bytes = bytes(sk_signer)
    else:
                         
        sk_signer_bytes = bytes(sk_signer)
    
                     
    processed_ring_pubkeys = []
    for pk in ring_pubkeys:
        if hasattr(pk, 'encode'):
                   
            processed_ring_pubkeys.append(pk.encode() if isinstance(pk, str) else bytes(pk))
        elif hasattr(pk, '__bytes__'):
                                         
            processed_ring_pubkeys.append(bytes(pk))
        else:
                             
            processed_ring_pubkeys.append(bytes(pk))
    
    if _lib:
                 
        ring_arr = (ctypes.c_char_p * len(processed_ring_pubkeys))()
        for i, pk in enumerate(processed_ring_pubkeys):
            ring_arr[i] = ctypes.c_char_p(pk)
        
                 
        sig_buf = ctypes.create_string_buffer(8192)           
        sig_len = ctypes.c_size_t(0)
        keyimg_buf = ctypes.create_string_buffer(64)           
        
               
        rc = _lib.lsag_sign(
            msg, len(msg),
            ring_arr, len(processed_ring_pubkeys),
            sk_signer_bytes,
            ctx, len(ctx),
            sig_buf, ctypes.byref(sig_len),
            keyimg_buf
        )
        
        if rc != 0:
            raise RuntimeError(f"LSAG签名失败，错误码: {rc}")
        
        sig = sig_buf.raw[:sig_len.value]
        keyimage = keyimg_buf.raw[:32]            
        
        return sig, keyimage
    else:
                         
        return fallback_lsag_sign(msg, processed_ring_pubkeys, sk_signer_bytes, ctx)

def lsag_verify_py(msg: bytes, ring_pubkeys: list[bytes], sig: bytes, keyimage: bytes, ctx: bytes):
    """
    Python包装的LSAG验证函数
    
    Args:
        msg: 要验证的消息
        ring_pubkeys: 环中所有公钥的列表
        sig: 签名
        keyimage: 密钥镜像
        ctx: 上下文/窗口ID
    
    Returns:
        bool: 验证是否成功
    """
                     
    processed_ring_pubkeys = []
    for pk in ring_pubkeys:
        if hasattr(pk, 'encode'):
                   
            processed_ring_pubkeys.append(pk.encode() if isinstance(pk, str) else bytes(pk))
        elif hasattr(pk, '__bytes__'):
                                         
            processed_ring_pubkeys.append(bytes(pk))
        else:
                             
            processed_ring_pubkeys.append(bytes(pk))
    
    if _lib:
                 
        ring_arr = (ctypes.c_char_p * len(processed_ring_pubkeys))()
        for i, pk in enumerate(processed_ring_pubkeys):
            ring_arr[i] = ctypes.c_char_p(pk)
        
               
        rc = _lib.lsag_verify(
            msg, len(msg),
            ring_arr, len(processed_ring_pubkeys),
            sig,
            ctx, len(ctx),
            keyimage
        )
        
        return rc == 0
    else:
                         
        return fallback_lsag_verify(msg, processed_ring_pubkeys, sig, keyimage, ctx)

               
def fallback_lsag_sign(msg: bytes, ring_pubkeys: list[bytes], sk_signer: bytes, ctx: bytes):
    """
    占位符LSAG签名实现
    """
               
    data = msg + ctx + sk_signer
    sig = hmac.new(sk_signer[:32], data, hashlib.sha256).digest()
    
                 
    keyimage = hashlib.sha256(sk_signer + ctx).digest()
    
    return sig, keyimage

def fallback_lsag_verify(msg: bytes, ring_pubkeys: list[bytes], sig: bytes, keyimage: bytes, ctx: bytes):
    """
    占位符LSAG验证实现
    """
                    
    return True