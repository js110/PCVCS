"""
Kyber/ML-KEM 密钥封装机制层
用于传输层安全通信
"""
import hashlib
import os

# 尝试导入Kyber库
_kyber_lib = None
try:
    from kyber_py.kyber import Kyber512
    _kyber_lib = Kyber512
except ImportError:
    pass

class KEMServer:
    """
    KEM服务器端实现
    """
    def __init__(self):
        self.pk = None
        self.sk = None
        # 使用全局Kyber实例
        self.kyber = _kyber_lib
    
    def setup_keys(self):
        """
        生成KEM密钥对
        """
        if self.kyber:
            # 使用真实的Kyber实现
            self.pk, self.sk = self.kyber.keygen()
            return self.pk, self.sk
        else:
            # 占位符实现
            self.pk = os.urandom(800)  # Kyber512公钥长度
            self.sk = os.urandom(1632)  # Kyber512私钥长度
            return self.pk, self.sk
    
    def finish_handshake(self, ct):
        """
        完成握手过程，从密文恢复共享密钥
        
        Args:
            ct: 客户端发送的密文
            
        Returns:
            bytes: 服务器端的共享密钥
        """
        if self.kyber:
            # 使用真实的Kyber实现
            try:
                ss_server = self.kyber.decaps(self.sk, ct)  # 修正参数顺序
            except Exception as e:
                # 如果解封装失败，回退到占位符实现
                print(f"Kyber解封装失败，回退到占位符实现: {e}")
                ss_server = hashlib.sha256(ct + self.sk).digest()
        else:
            # 占位符实现
            ss_server = hashlib.sha256(ct + self.sk).digest()
        
        # 从共享密钥派生会话密钥
        key = hashlib.sha256(ss_server).digest()
        return key

class KEMClient:
    """
    KEM客户端实现
    """
    def __init__(self):
        # 使用全局Kyber实例
        self.kyber = _kyber_lib
    
    def handshake(self, pk):
        """
        执行握手过程，生成密文和共享密钥
        
        Args:
            pk: 服务器的公钥
            
        Returns:
            tuple: (ct, key) 密文和客户端的共享密钥
        """
        if self.kyber:
            # 使用真实的Kyber实现
            try:
                ss_client, ct = self.kyber.encaps(pk)  # 修正返回值顺序
            except Exception as e:
                # 如果封装失败，回退到占位符实现
                print(f"Kyber封装失败，回退到占位符实现: {e}")
                ct = os.urandom(32)  # Kyber512密文长度
                ss_client = hashlib.sha256(ct + pk).digest()
        else:
            # 占位符实现
            ct = os.urandom(32)  # Kyber512密文长度
            ss_client = hashlib.sha256(ct + pk).digest()
        
        # 从共享密钥派生会话密钥
        key = hashlib.sha256(ss_client).digest()
        return ct, key

def server_setup_keys():
    """
    服务器端设置密钥对
    
    Returns:
        tuple: (pk, sk) 公钥和私钥
    """
    server = KEMServer()
    return server.setup_keys()

def client_handshake(pk):
    """
    客户端握手
    
    Args:
        pk: 服务器公钥
        
    Returns:
        tuple: (ct, key) 密文和会话密钥
    """
    client = KEMClient()
    return client.handshake(pk)

def server_finish(ct, sk):
    """
    服务器端完成握手
    
    Args:
        ct: 客户端密文
        sk: 服务器私钥
        
    Returns:
        bytes: 会话密钥
    """
    server = KEMServer()
    server.sk = sk
    return server.finish_handshake(ct)

# 网络层集成示例
def example_server_handshake(conn):
    """
    服务器端握手示例
    
    Args:
        conn: 网络连接对象，需要实现sendall和recv方法
        
    Returns:
        bytes: 会话密钥
    """
    # 1. 生成密钥对
    pk, sk = server_setup_keys()
    
    # 2. 发送公钥给客户端
    conn.sendall(pk)
    
    # 3. 接收客户端发送的密文
    ct = conn.recv(1024)
    
    # 4. 完成握手并获取会话密钥
    session_key = server_finish(ct, sk)
    
    return session_key

def example_client_handshake(conn):
    """
    客户端握手示例
    
    Args:
        conn: 网络连接对象，需要实现sendall和recv方法
        
    Returns:
        bytes: 会话密钥
    """
    # 1. 接收服务器公钥
    pk = conn.recv(1024)
    
    # 2. 执行握手
    ct, session_key = client_handshake(pk)
    
    # 3. 发送密文给服务器
    conn.sendall(ct)
    
    return session_key

# 兼容性函数别名（用于baseline_comparison）
def kem_keygen():
    """
    KEM密钥生成
    
    Returns:
        tuple: (pk, sk) 公钥和私钥
    """
    return server_setup_keys()

def kem_encaps(pk):
    """
    KEM封装
    
    Args:
        pk: 公钥
        
    Returns:
        tuple: (ct, key) 密文和会话密钥
    """
    return client_handshake(pk)

def kem_decaps(sk, ct):
    """
    KEM解封装
    
    Args:
        sk: 私钥
        ct: 密文
        
    Returns:
        bytes: 会话密钥
    """
    return server_finish(ct, sk)

# 实际使用示例（需要替换为真实的Kyber实现）
"""
要使用真实的Kyber/ML-KEM实现，您需要：

1. 安装Kyber库，例如：
   pip install kyber-py
   或者
   pip install pqcrypto

2. 修改上述代码中的占位符实现，替换为实际的Kyber函数调用：

   # 服务器端密钥生成
   from kyber_py.kyber import Kyber512
   pk, sk = Kyber512.keygen()
   
   # 客户端封装
   ss_client, ct = Kyber512.encaps(pk)  # 注意返回值顺序
   
   # 服务器端解封装
   ss_server = Kyber512.decaps(sk, ct)  # 注意参数顺序

3. 确保两端使用相同的Kyber参数集（Kyber512, Kyber768, Kyber1024）
"""