"""
Bulletproofs Python包装器
使用ctypes调用Rust库实现
"""
import ctypes
import sys
import os
import hashlib

                   
_lib = None
try:
                 
    if sys.platform.startswith('win'):
                          
        dll_path = os.path.join(os.path.dirname(__file__), '..', 'libbulletproofs.dll')
        dll_path = os.path.abspath(dll_path)
        if os.path.exists(dll_path):
            _lib = ctypes.CDLL(dll_path)
        else:
                       
            dll_path = os.path.join(os.getcwd(), 'libbulletproofs.dll')
            if os.path.exists(dll_path):
                _lib = ctypes.CDLL(dll_path)
            else:
                print(f"Bulletproofs库文件未找到: {dll_path}")
    elif sys.platform.startswith('darwin'):
               
        _lib = ctypes.CDLL("libbulletproofs.dylib")
    else:
               
        _lib = ctypes.CDLL("libbulletproofs.so")
except OSError as e:
                
    print(f"无法加载Bulletproofs库: {e}")
    _lib = None
except Exception as e:
    print(f"加载Bulletproofs库时出现未知错误: {e}")
    _lib = None

                 
if _lib:
    try:
                      
        _lib.bp_pedersen_commit.argtypes = [
            ctypes.c_uint64,         
            ctypes.c_uint64,            
            ctypes.c_char_p                          
        ]
        _lib.bp_pedersen_commit.restype = ctypes.c_int

                  
        _lib.bp_range_proof_prove.argtypes = [
            ctypes.c_uint64,         
            ctypes.c_uint64,     
            ctypes.c_uint64,     
            ctypes.c_uint64,            
            ctypes.c_char_p,                         
            ctypes.c_char_p,             
            ctypes.POINTER(ctypes.c_size_t)                 
        ]
        _lib.bp_range_proof_prove.restype = ctypes.c_int

                  
        _lib.bp_range_proof_verify.argtypes = [
            ctypes.c_uint64,     
            ctypes.c_uint64,     
            ctypes.c_char_p,                     
            ctypes.c_char_p,         
            ctypes.c_size_t              
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
                 
        commit_buf = ctypes.create_string_buffer(32)
        
               
        rc = _lib.bp_pedersen_commit(
            ctypes.c_uint64(value),
            ctypes.c_uint64(blinding),
            commit_buf
        )
        
        if rc != 0:
            raise RuntimeError(f"Pedersen承诺失败，错误码: {rc}")
        
        return commit_buf.raw
    else:
                         
        return fallback_pedersen_commit(value, blinding)

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
                 
        commit_buf = ctypes.create_string_buffer(32)
        proof_buf = ctypes.create_string_buffer(10240)         
        proof_len = ctypes.c_size_t(0)
        
               
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
                         
        return fallback_range_proof_prove(value, L, U, blinding)

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
                       
        if len(commit) != 32:
            raise ValueError("承诺值必须是32字节")
        
               
        rc = _lib.bp_range_proof_verify(
            ctypes.c_uint64(L),
            ctypes.c_uint64(U),
            commit,
            proof,
            ctypes.c_size_t(len(proof))
        )
        
        return rc == 0
    else:
                         
        return fallback_range_proof_verify(L, U, commit, proof)

               
def fallback_pedersen_commit(value: int, blinding: int) -> bytes:
    """
    占位符Pedersen承诺实现
    """
    commit = hashlib.sha256(f"{value}|{blinding}".encode()).digest()
    return commit

def fallback_range_proof_prove(value: int, L: int, U: int, blinding: int) -> tuple[bytes, bytes]:
    """
    占位符范围证明生成实现
    """
    commit = hashlib.sha256(f"{value}|{blinding}".encode()).digest()
    proof = hashlib.sha256(f"{value}|{L}|{U}|{blinding}".encode()).digest()
    return commit, proof

def fallback_range_proof_verify(L: int, U: int, commit: bytes, proof: bytes) -> bool:
    """
    占位符范围证明验证实现
    """
                    
    return True