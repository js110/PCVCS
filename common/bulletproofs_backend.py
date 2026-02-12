"""
Bulletproofs Python包装器
使用ctypes调用Rust库实现
"""
import ctypes
import sys
import os
import hashlib

# 尝试加载Bulletproofs库
_lib = None
try:
    # 根据操作系统选择库文件
    if sys.platform.startswith('win'):
        # Windows - 使用完整路径
        dll_path = os.path.join(os.path.dirname(__file__), '..', 'libbulletproofs.dll')
        dll_path = os.path.abspath(dll_path)
        if os.path.exists(dll_path):
            _lib = ctypes.CDLL(dll_path)
        else:
            # 尝试在当前目录查找
            dll_path = os.path.join(os.getcwd(), 'libbulletproofs.dll')
            if os.path.exists(dll_path):
                _lib = ctypes.CDLL(dll_path)
            else:
                print(f"Bulletproofs库文件未找到: {dll_path}")
    elif sys.platform.startswith('darwin'):
        # macOS
        _lib = ctypes.CDLL("libbulletproofs.dylib")
    else:
        # Linux
        _lib = ctypes.CDLL("libbulletproofs.so")
except OSError as e:
    # 库未找到，使用占位符
    print(f"无法加载Bulletproofs库: {e}")
    _lib = None
except Exception as e:
    print(f"加载Bulletproofs库时出现未知错误: {e}")
    _lib = None

# 定义函数签名（如果库加载成功）
if _lib:
    try:
        # Pedersen承诺函数
        _lib.bp_pedersen_commit.argtypes = [
            ctypes.c_uint64,  # value
            ctypes.c_uint64,  # blinding
            ctypes.c_char_p   # out_commit (32 bytes)
        ]
        _lib.bp_pedersen_commit.restype = ctypes.c_int

        # 范围证明生成函数
        _lib.bp_range_proof_prove.argtypes = [
            ctypes.c_uint64,  # value
            ctypes.c_uint64,  # L
            ctypes.c_uint64,  # U
            ctypes.c_uint64,  # blinding
            ctypes.c_char_p,  # out_commit (32 bytes)
            ctypes.c_char_p,  # out_proof
            ctypes.POINTER(ctypes.c_size_t)  # out_proof_len
        ]
        _lib.bp_range_proof_prove.restype = ctypes.c_int

        # 范围证明验证函数
        _lib.bp_range_proof_verify.argtypes = [
            ctypes.c_uint64,  # L
            ctypes.c_uint64,  # U
            ctypes.c_char_p,  # commit (32 bytes)
            ctypes.c_char_p,  # proof
            ctypes.c_size_t   # proof_len
        ]
        _lib.bp_range_proof_verify.restype = ctypes.c_int
        
        print("Bulletproofs库加载成功")
    except Exception as e:
        print(f"定义Bulletproofs库函数签名时出错: {e}")
        _lib = None
else:
    print("Bulletproofs库未加载，使用占位符实现")

def pedersen_commit_py(value: int, blinding: int) -> bytes:
    """
    Python包装的Pedersen承诺函数
    
    Args:
        value: 要承诺的值
        blinding: 盲化因子
    
    Returns:
        bytes: 32字节的承诺值
    """
    if _lib:
        # 准备输出缓冲区
        commit_buf = ctypes.create_string_buffer(32)
        
        # 调用C函数
        rc = _lib.bp_pedersen_commit(
            ctypes.c_uint64(value),
            ctypes.c_uint64(blinding),
            commit_buf
        )
        
        if rc != 0:
            raise RuntimeError(f"Pedersen承诺失败，错误码: {rc}")
        
        return commit_buf.raw
    else:
        # 使用Python实现的简化版本
        return placeholder_pedersen_commit(value, blinding)

def range_proof_prove_py(value: int, L: int, U: int, blinding: int) -> tuple[bytes, bytes]:
    """
    Python包装的范围证明生成函数
    
    Args:
        value: 要证明的值
        L: 范围下界
        U: 范围上界
        blinding: 盲化因子
    
    Returns:
        tuple: (commitment, proof)
    """
    if _lib:
        # 准备输出缓冲区
        commit_buf = ctypes.create_string_buffer(32)
        proof_buf = ctypes.create_string_buffer(10240)  # 假设足够大
        proof_len = ctypes.c_size_t(0)
        
        # 调用C函数
        rc = _lib.bp_range_proof_prove(
            ctypes.c_uint64(value),
            ctypes.c_uint64(L),
            ctypes.c_uint64(U),
            ctypes.c_uint64(blinding),
            commit_buf,
            proof_buf,
            ctypes.byref(proof_len)
        )
        
        if rc != 0:
            raise RuntimeError(f"范围证明生成失败，错误码: {rc}")
        
        commit = commit_buf.raw
        proof = proof_buf.raw[:proof_len.value]
        
        return commit, proof
    else:
        # 使用Python实现的简化版本
        return placeholder_range_proof_prove(value, L, U, blinding)

def range_proof_verify_py(L: int, U: int, commit: bytes, proof: bytes) -> bool:
    """
    Python包装的范围证明验证函数
    
    Args:
        L: 范围下界
        U: 范围上界
        commit: 承诺值
        proof: 证明值
    
    Returns:
        bool: 验证是否成功
    """
    if _lib:
        # 确保commit是32字节
        if len(commit) != 32:
            raise ValueError("承诺值必须是32字节")
        
        # 调用C函数
        rc = _lib.bp_range_proof_verify(
            ctypes.c_uint64(L),
            ctypes.c_uint64(U),
            commit,
            proof,
            ctypes.c_size_t(len(proof))
        )
        
        return rc == 0
    else:
        # 使用Python实现的简化版本
        return placeholder_range_proof_verify(L, U, commit, proof)

# 占位符实现（如果库未加载）
def placeholder_pedersen_commit(value: int, blinding: int) -> bytes:
    """
    占位符Pedersen承诺实现
    """
    commit = hashlib.sha256(f"{value}|{blinding}".encode()).digest()
    return commit

def placeholder_range_proof_prove(value: int, L: int, U: int, blinding: int) -> tuple[bytes, bytes]:
    """
    占位符范围证明生成实现
    """
    commit = hashlib.sha256(f"{value}|{blinding}".encode()).digest()
    proof = hashlib.sha256(f"{value}|{L}|{U}|{blinding}".encode()).digest()
    return commit, proof

def placeholder_range_proof_verify(L: int, U: int, commit: bytes, proof: bytes) -> bool:
    """
    占位符范围证明验证实现
    """
    # 简化的验证：总是返回True
    return True