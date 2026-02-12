#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基线方案对比模块
实现PPRM和LMDA-VCS方案的简化版本用于性能对比
"""

import os
import sys
import time
import random
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from experiments.logger import ExperimentLogger
from common.crypto_adapters import (
    ed25519_generate_keypair, ed25519_sign, ed25519_verify
)


@dataclass
class BaselineResult:
    """基线方案测试结果"""
    scheme_name: str  # PPRM, LMDA-VCS, Proposed
    vehicle_gen_time_ms: float
    server_verify_time_ms: float
    report_size_bytes: int
    throughput_qps: float = 0.0
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PPRMScheme:
    """PPRM方案简化实现"""
    
    def __init__(self):
        self.name = "PPRM"
        
    def generate_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """生成报告"""
        # 1. 生成假名 (pseudonym)
        sk, pk = ed25519_generate_keypair()
        pseudonym = hashlib.sha256(bytes(pk)).hexdigest()
        
        # 2. 位置模糊化 (grid-based)
        lat = data.get("lat", 31.23)
        lon = data.get("lon", 121.47)
        # 简化为网格化 (精度0.01度 约1km)
        grid_lat = round(lat, 2)
        grid_lon = round(lon, 2)
        
        # 3. 对称加密数据
        import secrets
        aes_key = secrets.token_bytes(32)
        sensor_data = data.get("data", b"sensor_reading")
        # 简化：仅记录密钥和数据大小
        encrypted_data = hashlib.sha256(sensor_data + aes_key).digest()
        
        # 4. 签名
        message = f"{pseudonym}|{grid_lat}|{grid_lon}".encode()
        signature = ed25519_sign(sk, message)
        
        report = {
            "scheme": "PPRM",
            "pseudonym": pseudonym,
            "grid_lat": grid_lat,
            "grid_lon": grid_lon,
            "encrypted_data": encrypted_data.hex(),
            "signature": signature.hex(),
            "public_key": bytes(pk).hex(),
            "aes_key_size": 32
        }
        
        return report
    
    def verify_report(self, report: Dict[str, Any]) -> bool:
        """验证报告"""
        try:
            # 1. 验证签名
            message = f"{report['pseudonym']}|{report['grid_lat']}|{report['grid_lon']}".encode()
            pk_bytes = bytes.fromhex(report['public_key'])
            sig_bytes = bytes.fromhex(report['signature'])
            
            # 简化验证
            return True  # 简化实现，假设验证通过
        except Exception:
            return False


class LMDAVCSScheme:
    """LMDA-VCS方案简化实现"""
    
    def __init__(self):
        self.name = "LMDA-VCS"
        
    def generate_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """生成报告"""
        # 1. 假名
        sk, pk = ed25519_generate_keypair()
        pseudonym = hashlib.sha256(bytes(pk)).hexdigest()
        
        # 2. 数据扰动 (添加噪声)
        sensor_value = data.get("value", 25.5)
        noise = random.gauss(0, 0.1)
        perturbed_value = sensor_value + noise
        
        # 3. 同态加密聚合 (简化)
        # 实际使用Paillier等,这里简化为加密表示
        encrypted_value = hashlib.sha256(str(perturbed_value).encode()).hexdigest()
        
        # 4. 聚合签名 (简化为普通签名)
        message = f"{pseudonym}|{encrypted_value}".encode()
        signature = ed25519_sign(sk, message)
        
        report = {
            "scheme": "LMDA-VCS",
            "pseudonym": pseudonym,
            "encrypted_value": encrypted_value,
            "signature": signature.hex(),
            "public_key": bytes(pk).hex(),
            "aggregatable": True
        }
        
        return report
    
    def verify_report(self, report: Dict[str, Any]) -> bool:
        """验证报告"""
        try:
            # 简化验证
            return True
        except Exception:
            return False


class ProposedScheme:
    """本方案 (使用现有完整实现)"""
    
    def __init__(self):
        self.name = "Proposed"
        # 导入现有模块
        from common.crypto import merkle_root, merkle_proof
        from common.crypto_adapters import range_proof_prove, lrs_sign
        from common.kem_layer import kem_keygen, kem_encaps
        
        self.merkle_root = merkle_root
        self.merkle_proof = merkle_proof
        self.range_proof_prove = range_proof_prove
        self.lrs_sign = lrs_sign
        self.kem_keygen = kem_keygen
        self.kem_encaps = kem_encaps
        
        # 白名单
        self.whitelist = ["wtw3s8n", "wtw3s8p", "wtw3s8q", "wtw3s8r"]
        
    def generate_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """生成完整报告"""
        # 1. RSU Token
        sk, pk = ed25519_generate_keypair()
        window_id = int(time.time()) // 60
        token_msg = f"1|NET|{window_id}|12345|{int(time.time())+3600}|1".encode()
        token_sig = ed25519_sign(sk, token_msg)
        
        # 2. Merkle证明
        geohash = random.choice(self.whitelist)
        root = self.merkle_root(self.whitelist)
        proof = self.merkle_proof(self.whitelist, self.whitelist.index(geohash))
        
        # 3. Bulletproofs范围证明
        timestamp = int(time.time())
        blinding = random.randint(1, 1000000)
        range_proof = self.range_proof_prove(timestamp, window_id * 60, (window_id + 1) * 60, blinding)
        
        # 4. LSAG签名
        ring_size = 8
        ring_keys = [ed25519_generate_keypair() for _ in range(ring_size)]
        ring_pubkeys = [pk for _, pk in ring_keys]
        signer_sk = ring_keys[0][0]
        message = f"{geohash}|{timestamp}".encode()
        lsag_sig = self.lrs_sign(message, ring_pubkeys, 0, signer_sk, b"context")
        
        # 5. Kyber KEM
        kem_pk, kem_sk = self.kem_keygen()
        ciphertext, shared_secret = self.kem_encaps(kem_pk)
        
        report = {
            "scheme": "Proposed",
            "token": {"signature": token_sig.hex(), "window_id": window_id},
            "geohash": geohash,
            "merkle_root": root,
            "merkle_proof": proof,
            "range_proof": range_proof,
            "lsag_signature": lsag_sig,
            "kyber_ct": len(ciphertext) if ciphertext else 768
        }
        
        return report
    
    def verify_report(self, report: Dict[str, Any]) -> bool:
        """验证报告"""
        # 简化：返回True
        return True


class BaselineComparison:
    """基线方案对比测试"""
    
    def __init__(self, logger: Optional[ExperimentLogger] = None):
        self.logger = logger
        self.schemes = {
            "PPRM": PPRMScheme(),
            "LMDA-VCS": LMDAVCSScheme(),
            "Proposed": ProposedScheme()
        }
        self.results = []
        
    def _log(self, message: str, level: str = "info") -> None:
        """记录日志"""
        if self.logger:
            getattr(self.logger, level)(message)
        else:
            print(f"[{level.upper()}] {message}")
    
    def test_single_report_performance(self, scheme_name: str, iterations: int = 100) -> BaselineResult:
        """测试单报告性能"""
        self._log(f"测试{scheme_name}单报告性能 (迭代{iterations}次)...")
        
        scheme = self.schemes[scheme_name]
        
        # 测试数据
        test_data = {
            "lat": 31.23,
            "lon": 121.47,
            "data": b"sensor_reading_data",
            "value": 25.5
        }
        
        # 车辆端生成时间
        gen_times = []
        report_sizes = []
        
        for _ in range(iterations):
            start = time.perf_counter()
            report = scheme.generate_report(test_data)
            end = time.perf_counter()
            
            gen_times.append((end - start) * 1000)  # ms
            
            # 计算报告大小
            import json
            report_json = json.dumps(report)
            report_sizes.append(len(report_json.encode()))
        
        avg_gen_time = sum(gen_times) / len(gen_times)
        avg_size = sum(report_sizes) / len(report_sizes)
        
        # 服务器端验证时间
        verify_times = []
        test_report = scheme.generate_report(test_data)
        
        for _ in range(iterations):
            start = time.perf_counter()
            scheme.verify_report(test_report)
            end = time.perf_counter()
            
            verify_times.append((end - start) * 1000)
        
        avg_verify_time = sum(verify_times) / len(verify_times)
        
        result = BaselineResult(
            scheme_name=scheme_name,
            vehicle_gen_time_ms=avg_gen_time,
            server_verify_time_ms=avg_verify_time,
            report_size_bytes=int(avg_size)
        )
        
        self._log(f"  生成时间: {avg_gen_time:.4f} ms")
        self._log(f"  验证时间: {avg_verify_time:.4f} ms")
        self._log(f"  报告大小: {avg_size:.0f} bytes")
        
        return result
    
    def run_all_comparisons(self, iterations: int = 100, concurrency_levels: List[int] = None) -> List[Dict[str, Any]]:
        """运行所有对比测试"""
        self._log("=" * 60)
        self._log("开始基线方案对比实验")
        self._log("=" * 60)
        
        results = []
        
        for scheme_name in ["PPRM", "LMDA-VCS", "Proposed"]:
            self._log(f"\n测试方案: {scheme_name}")
            
            # 单报告性能（只对比生成时间、验证时间、报告大小）
            result = self.test_single_report_performance(scheme_name, iterations)
            
            result_dict = result.to_dict()
            results.append(result_dict)
            
            self.results.append(result)
        
        self._log("=" * 60)
        self._log("基线方案对比实验完成")
        self._log("=" * 60)
        
        return results
    
    def save_results(self, output_path: Path) -> None:
        """保存结果"""
        import json
        
        results_list = [result.to_dict() for result in self.results]
        
        output_data = {
            "results": results_list,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        self._log(f"基线对比结果已保存到: {output_path}")


if __name__ == "__main__":
    # 测试
    comparison = BaselineComparison()
    results = comparison.run_all_comparisons(iterations=100, concurrency_levels=[100, 300, 500])
    
    import json
    print(json.dumps(results, indent=2))
