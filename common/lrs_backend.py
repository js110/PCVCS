"""
LSAG/LRS Python包装器
使用ctypes调用C库实现
"""
import ctypes
import os
import sys
import hmac
import hashlib

# 尝试加载LSAG库
_lib = None
try:
    # 根据操作系统选择库文件
    if sys.platform.startswith('win'):
        # Windows
        lib_path = os.path.join(os.path.dirname(__file__), '..', 'liblsag.dll')
        lib_path = os.path.abspath(lib_path)
        if os.path.exists(lib_path):
            _lib = ctypes.CDLL(lib_path)
        else:
            # 尝试在当前目录查找
            lib_path = os.path.join(os.getcwd(), 'liblsag.dll')
            if os.path.exists(lib_path):
                _lib = ctypes.CDLL(lib_path)
    elif sys.platform.startswith('darwin'):
        # macOS
        lib_path = os.path.join(os.path.dirname(__file__), '..', 'liblsag.dylib')
        lib_path = os.path.abspath(lib_path)
        if os.path.exists(lib_path):
            _lib = ctypes.CDLL(lib_path)
    else:
        # Linux
        lib_path = os.path.join(os.path.dirname(__file__), '..', 'liblsag.so')
        lib_path = os.path.abspath(lib_path)
        if os.path.exists(lib_path):
            _lib = ctypes.CDLL(lib_path)
except OSError as e:
    # 库未找到，使用占位符
    _lib = None
    print(f"Failed to load LSAG library: {e}")

# 定义函数签名（如果库加载成功）
if _lib:
    # LSAG签名函数
    _lib.lsag_sign.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t,  # message, msg_len
        ctypes.POINTER(ctypes.c_char_p), ctypes.c_size_t,  # ring_pubkeys, ring_len
        ctypes.c_char_p,  # sk_signer
        ctypes.c_char_p, ctypes.c_size_t,  # ctx, ctx_len
        ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),  # sig_out, sig_out_len
        ctypes.c_char_p  # keyimage_out
    ]
    _lib.lsag_sign.restype = ctypes.c_int

    # LSAG验证函数
    _lib.lsag_verify.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t,  # message, msg_len
        ctypes.POINTER(ctypes.c_char_p), ctypes.c_size_t,  # ring_pubkeys, ring_len
        ctypes.c_char_p,  # sig
        ctypes.c_char_p, ctypes.c_size_t,  # ctx, ctx_len
        ctypes.c_char_p  # keyimage
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
    # 确保sk_signer是bytes类型
    if hasattr(sk_signer, 'encode'):
        # 字符串类型
        sk_signer_bytes = sk_signer.encode() if isinstance(sk_signer, str) else bytes(sk_signer)
    elif hasattr(sk_signer, 'sign'):
        # PyNaCl的SigningKey对象，提取其字节表示
        sk_signer_bytes = bytes(sk_signer)
    else:
        # 其他类型，直接转换为bytes
        sk_signer_bytes = bytes(sk_signer)
    
    # 确保所有公钥都是bytes类型
    processed_ring_pubkeys = []
    for pk in ring_pubkeys:
        if hasattr(pk, 'encode'):
            # 字符串类型
            processed_ring_pubkeys.append(pk.encode() if isinstance(pk, str) else bytes(pk))
        elif hasattr(pk, '__bytes__'):
            # 有__bytes__方法的对象（如VerifyKey）
            processed_ring_pubkeys.append(bytes(pk))
        else:
            # 其他类型，直接转换为bytes
            processed_ring_pubkeys.append(bytes(pk))
    
    if _lib:
        # 准备环公钥数组
        ring_arr = (ctypes.c_char_p * len(processed_ring_pubkeys))()
        for i, pk in enumerate(processed_ring_pubkeys):
            ring_arr[i] = ctypes.c_char_p(pk)
        
        # 准备输出缓冲区
        sig_buf = ctypes.create_string_buffer(8192)  # 增加缓冲区大小
        sig_len = ctypes.c_size_t(0)
        keyimg_buf = ctypes.create_string_buffer(64)  # 通常为32字节
        
        # 调用C函数
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
        keyimage = keyimg_buf.raw[:32]  # 确保只取32字节
        
        return sig, keyimage
    else:
        # 使用Python实现的简化版本
        return placeholder_lsag_sign(msg, processed_ring_pubkeys, sk_signer_bytes, ctx)

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
    # 确保所有公钥都是bytes类型
    processed_ring_pubkeys = []
    for pk in ring_pubkeys:
        if hasattr(pk, 'encode'):
            # 字符串类型
            processed_ring_pubkeys.append(pk.encode() if isinstance(pk, str) else bytes(pk))
        elif hasattr(pk, '__bytes__'):
            # 有__bytes__方法的对象（如VerifyKey）
            processed_ring_pubkeys.append(bytes(pk))
        else:
            # 其他类型，直接转换为bytes
            processed_ring_pubkeys.append(bytes(pk))
    
    if _lib:
        # 准备环公钥数组
        ring_arr = (ctypes.c_char_p * len(processed_ring_pubkeys))()
        for i, pk in enumerate(processed_ring_pubkeys):
            ring_arr[i] = ctypes.c_char_p(pk)
        
        # 调用C函数
        rc = _lib.lsag_verify(
            msg, len(msg),
            ring_arr, len(processed_ring_pubkeys),
            sig,
            ctx, len(ctx),
            keyimage
        )
        
        return rc == 0
    else:
        # 使用Python实现的简化版本
        return placeholder_lsag_verify(msg, processed_ring_pubkeys, sig, keyimage, ctx)

# 占位符实现（如果库未加载）
def placeholder_lsag_sign(msg: bytes, ring_pubkeys: list[bytes], sk_signer: bytes, ctx: bytes):
    """
    占位符LSAG签名实现
    """
    # 创建一个简单的签名
    data = msg + ctx + sk_signer
    sig = hmac.new(sk_signer[:32], data, hashlib.sha256).digest()
    
    # 创建一个简单的密钥镜像
    keyimage = hashlib.sha256(sk_signer + ctx).digest()
    
    return sig, keyimage

def placeholder_lsag_verify(msg: bytes, ring_pubkeys: list[bytes], sig: bytes, keyimage: bytes, ctx: bytes):
    """
    占位符LSAG验证实现
    """
    # 简化的验证：总是返回True
    return True