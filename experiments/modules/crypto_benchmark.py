#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
密码学原语基准测试模块
"""

import os
import sys
import time
from pathlib import Path
from typing import List, Optional

# 添加项目路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from experiments.models.benchmark_result import BenchmarkResult, BenchmarkResultCollection
from experiments.logger import ExperimentLogger
from common.crypto_adapters import (
    ed25519_generate_keypair,
    ed25519_sign,
    ed25519_verify,
    lrs_sign,
    lrs_verify,
    range_proof_prove,
    range_proof_verify,
    pedersen_commit
)
from common.crypto import merkle_root, merkle_proof, merkle_verify


class CryptoBenchmark:
    """密码学原语基准测试类"""
    
    def __init__(self, logger: Optional[ExperimentLogger] = None):
        """
        初始化基准测试器
        
        Args:
            logger: 日志记录器
        """
        self.logger = logger
        self.results = BenchmarkResultCollection()
    
    def _log(self, message: str, level: str = "info") -> None:
        """记录日志"""
        if self.logger:
            getattr(self.logger, level)(message)
    
    def benchmark_ed25519(self, iterations: int = 100) -> BenchmarkResult:
        """
        测试Ed25519签名和验证性能
        
        Args:
            iterations: 迭代次数
        
        Returns:
            BenchmarkResult实例
        """
        self._log("开始Ed25519签名和验证基准测试...")
        
        # 生成测试密钥对
        sk, pk = ed25519_generate_keypair()
        
        # 测试数据
        message = b"test message for Ed25519 signature benchmark" * 10
        
        # 签名性能测试
        sign_times = []
        signature = None
        for i in range(iterations):
            start = time.perf_counter()
            signature = ed25519_sign(sk, message)
            end = time.perf_counter()
            sign_times.append((end - start) * 1000)  # 转换为毫秒
        
        sign_result = BenchmarkResult.from_measurements(
            operation="Ed25519_Sign",
            times_ms=sign_times,
            size_bytes=len(signature) if signature else 64,
            parameters={"message_size": len(message)}
        )
        
        # 验证性能测试
        verify_times = []
        if signature is not None:
            for i in range(iterations):
                start = time.perf_counter()
                result = ed25519_verify(pk, message, signature)
                end = time.perf_counter()
                verify_times.append((end - start) * 1000)
        
        verify_result = BenchmarkResult.from_measurements(
            operation="Ed25519_Verify",
            times_ms=verify_times,
            size_bytes=len(signature) if signature else 64,
            parameters={"message_size": len(message)}
        )
        
        self.results.add(sign_result)
        self.results.add(verify_result)
        
        self._log(f"Ed25519签名: {sign_result.avg_time_ms:.4f} ms")
        self._log(f"Ed25519验证: {verify_result.avg_time_ms:.4f} ms")
        self._log(f"签名大小: {sign_result.size_bytes} bytes")
        
        return sign_result
    
    def benchmark_merkle_tree(self, leaf_counts: List[int] = None) -> List[BenchmarkResult]:
        """
        测试Merkle树生成和验证性能
        
        Args:
            leaf_counts: 叶子数量列表
        
        Returns:
            BenchmarkResult列表
        """
        if leaf_counts is None:
            leaf_counts = [10, 50, 100, 200]
        
        self._log("开始Merkle树基准测试...")
        
        results = []
        
        for leaf_count in leaf_counts:
            self._log(f"测试Merkle树 - {leaf_count}个叶子...")
            
            # 生成测试叶子节点
            leaves = [f"leaf_{i}" for i in range(leaf_count)]
            
            # 测试根生成时间
            root_times = []
            for _ in range(50):  # 减少迭代次数因为Merkle树计算较慢
                start = time.perf_counter()
                root = merkle_root(leaves)
                end = time.perf_counter()
                root_times.append((end - start) * 1000)
            
            root_result = BenchmarkResult.from_measurements(
                operation=f"Merkle_Root_Gen",
                times_ms=root_times,
                size_bytes=len(root) // 2 if root else 32,  # hex string to bytes
                parameters={"leaf_count": leaf_count}
            )
            
            # 测试证明生成和验证时间
            root = merkle_root(leaves)
            test_leaf_index = 0  # 使用第一个叶子的索引
            
            proof_gen_times = []
            proof_size = 0
            for _ in range(50):
                start = time.perf_counter()
                proof = merkle_proof(leaves, test_leaf_index)
                end = time.perf_counter()
                proof_gen_times.append((end - start) * 1000)
                if proof:
                    # 估算证明大小：每个兄弟节点32字节
                    proof_size = len(proof) * 32 + 32  # siblings + leaf
            
            proof_gen_result = BenchmarkResult.from_measurements(
                operation=f"Merkle_Proof_Gen",
                times_ms=proof_gen_times,
                size_bytes=proof_size,
                parameters={"leaf_count": leaf_count}
            )
            
            # 测试证明验证时间
            proof = merkle_proof(leaves, test_leaf_index)
            test_leaf = leaves[test_leaf_index]
            verify_times = []
            for _ in range(50):
                start = time.perf_counter()
                result = merkle_verify(test_leaf, proof, root, test_leaf_index)
                end = time.perf_counter()
                verify_times.append((end - start) * 1000)
            
            verify_result = BenchmarkResult.from_measurements(
                operation=f"Merkle_Proof_Verify",
                times_ms=verify_times,
                size_bytes=proof_size,
                parameters={"leaf_count": leaf_count}
            )
            
            self.results.add(root_result)
            self.results.add(proof_gen_result)
            self.results.add(verify_result)
            results.extend([root_result, proof_gen_result, verify_result])
            
            self._log(f"  根生成: {root_result.avg_time_ms:.4f} ms")
            self._log(f"  证明生成: {proof_gen_result.avg_time_ms:.4f} ms")
            self._log(f"  证明验证: {verify_result.avg_time_ms:.4f} ms")
            self._log(f"  证明大小: {proof_size} bytes")
        
        return results
    
    def benchmark_bulletproofs(self, batch_sizes: List[int] = None) -> List[BenchmarkResult]:
        """
        测试Bulletproofs范围证明性能
        
        Args:
            batch_sizes: 批量大小列表
        
        Returns:
            BenchmarkResult列表
        """
        if batch_sizes is None:
            batch_sizes = [1, 10, 100]
        
        self._log("开始Bulletproofs范围证明基准测试...")
        
        results = []
        
        for batch_size in batch_sizes:
            self._log(f"测试Bulletproofs - 批量大小{batch_size}...")
            
            # 测试参数
            value = 1234567890
            lower_bound = 0
            upper_bound = 2**32 - 1
            blinding = 42
            
            # 测试证明生成时间
            prove_times = []
            proof_size = 0
            for _ in range(batch_size):
                start = time.perf_counter()
                proof = range_proof_prove(value, lower_bound, upper_bound, blinding)
                end = time.perf_counter()
                prove_times.append((end - start) * 1000)
                if proof:
                    # 估算证明大小
                    import json
                    proof_size = len(json.dumps(proof).encode())
            
            prove_result = BenchmarkResult.from_measurements(
                operation=f"Bulletproofs_Prove",
                times_ms=prove_times,
                size_bytes=proof_size,
                parameters={"batch_size": batch_size, "range": f"[{lower_bound}, {upper_bound}]"}
            )
            
            # 测试证明验证时间
            proof = range_proof_prove(value, lower_bound, upper_bound, blinding)
            verify_times = []
            for _ in range(batch_size):
                start = time.perf_counter()
                result = range_proof_verify(proof)
                end = time.perf_counter()
                verify_times.append((end - start) * 1000)
            
            verify_result = BenchmarkResult.from_measurements(
                operation=f"Bulletproofs_Verify",
                times_ms=verify_times,
                size_bytes=proof_size,
                parameters={"batch_size": batch_size, "range": f"[{lower_bound}, {upper_bound}]"}
            )
            
            self.results.add(prove_result)
            self.results.add(verify_result)
            results.extend([prove_result, verify_result])
            
            self._log(f"  证明生成: {prove_result.avg_time_ms:.4f} ms")
            self._log(f"  证明验证: {verify_result.avg_time_ms:.4f} ms")
            self._log(f"  证明大小: {proof_size} bytes")
        
        return results

    def benchmark_lsag(self, ring_sizes: List[int] = None) -> List[BenchmarkResult]:
        """
        测试LSAG环签名性能
        
        Args:
            ring_sizes: 环大小列表
        
        Returns:
            BenchmarkResult列表
        """
        if ring_sizes is None:
            ring_sizes = [4, 8, 16]
        
        self._log("开始LSAG环签名基准测试...")
        
        results = []
        
        for ring_size in ring_sizes:
            self._log(f"测试LSAG - 环大小{ring_size}...")
            
            # 生成环成员密钥对
            ring_keys = []
            for _ in range(ring_size):
                sk, pk = ed25519_generate_keypair()
                ring_keys.append((sk, pk))
            
            # 选择签名者（第一个成员）
            signer_sk, signer_pk = ring_keys[0]
            ring_pubkeys = [pk for _, pk in ring_keys]
            
            # 测试消息
            message = b"test message for LSAG ring signature"
            context = b"test_context"
            
            # 测试签名生成时间
            sign_times = []
            signature = None
            for _ in range(50):  # LSAG较慢，减少迭代次数
                start = time.perf_counter()
                signature = lrs_sign(message, ring_pubkeys, 0, signer_sk, context)
                end = time.perf_counter()
                sign_times.append((end - start) * 1000)
            
            # 估算签名大小
            import json
            sig_size = len(json.dumps(signature).encode()) if signature else 0
            
            sign_result = BenchmarkResult.from_measurements(
                operation=f"LSAG_Sign",
                times_ms=sign_times,
                size_bytes=sig_size,
                parameters={"ring_size": ring_size}
            )
            
            # 测试签名验证时间
            verify_times = []
            if signature:
                for _ in range(50):
                    start = time.perf_counter()
                    result = lrs_verify(message, signature, ring_pubkeys)
                    end = time.perf_counter()
                    verify_times.append((end - start) * 1000)
            
            verify_result = BenchmarkResult.from_measurements(
                operation=f"LSAG_Verify",
                times_ms=verify_times,
                size_bytes=sig_size,
                parameters={"ring_size": ring_size}
            )
            
            self.results.add(sign_result)
            self.results.add(verify_result)
            results.extend([sign_result, verify_result])
            
            self._log(f"  签名生成: {sign_result.avg_time_ms:.4f} ms")
            self._log(f"  签名验证: {verify_result.avg_time_ms:.4f} ms")
            self._log(f"  签名大小: {sig_size} bytes")
        
        return results
    
    def benchmark_kyber(self, iterations: int = 100) -> BenchmarkResult:
        """
        测试Kyber密钥协商性能
        
        Args:
            iterations: 迭代次数
        
        Returns:
            BenchmarkResult实例
        """
        self._log("开始Kyber密钥协商基准测试...")
        
        try:
            # 尝试导入Kyber（如果可用）
            from common.kem_layer import kem_keygen, kem_encaps, kem_decaps
            
            # 测试密钥生成
            keygen_times = []
            for _ in range(iterations):
                start = time.perf_counter()
                pk, sk = kem_keygen()
                end = time.perf_counter()
                keygen_times.append((end - start) * 1000)
            
            keygen_result = BenchmarkResult.from_measurements(
                operation="Kyber_KeyGen",
                times_ms=keygen_times,
                size_bytes=len(pk) if pk else 800,  # Kyber512公钥约800字节
                parameters={"algorithm": "Kyber512"}
            )
            
            # 测试封装
            pk, sk = kem_keygen()
            encaps_times = []
            for _ in range(iterations):
                start = time.perf_counter()
                ct, ss = kem_encaps(pk)
                end = time.perf_counter()
                encaps_times.append((end - start) * 1000)
            
            encaps_result = BenchmarkResult.from_measurements(
                operation="Kyber_Encaps",
                times_ms=encaps_times,
                size_bytes=len(ct) if ct else 768,  # Kyber512密文约768字节
                parameters={"algorithm": "Kyber512"}
            )
            
            # 测试解封装
            ct, ss_expected = kem_encaps(pk)
            decaps_times = []
            for _ in range(iterations):
                start = time.perf_counter()
                ss = kem_decaps(sk, ct)
                end = time.perf_counter()
                decaps_times.append((end - start) * 1000)
            
            decaps_result = BenchmarkResult.from_measurements(
                operation="Kyber_Decaps",
                times_ms=decaps_times,
                size_bytes=len(ss) if ss else 32,  # 共享密钥32字节
                parameters={"algorithm": "Kyber512"}
            )
            
            self.results.add(keygen_result)
            self.results.add(encaps_result)
            self.results.add(decaps_result)
            
            # 计算完整握手时间
            total_time = keygen_result.avg_time_ms + encaps_result.avg_time_ms + decaps_result.avg_time_ms
            
            self._log(f"  密钥生成: {keygen_result.avg_time_ms:.4f} ms")
            self._log(f"  封装: {encaps_result.avg_time_ms:.4f} ms")
            self._log(f"  解封装: {decaps_result.avg_time_ms:.4f} ms")
            self._log(f"  完整握手: {total_time:.4f} ms")
            
            return keygen_result
            
        except ImportError:
            self._log("Kyber库不可用，使用占位符实现", "warning")
            
            # 使用占位符实现
            handshake_times = []
            for _ in range(iterations):
                start = time.perf_counter()
                # 模拟密钥协商过程
                time.sleep(0.001)  # 模拟1ms的计算时间
                end = time.perf_counter()
                handshake_times.append((end - start) * 1000)
            
            handshake_result = BenchmarkResult.from_measurements(
                operation="Kyber_Handshake_Placeholder",
                times_ms=handshake_times,
                size_bytes=1600,  # 估算总大小
                parameters={"algorithm": "Kyber512", "note": "placeholder"}
            )
            
            self.results.add(handshake_result)
            self._log(f"  完整握手（占位符）: {handshake_result.avg_time_ms:.4f} ms")
            
            return handshake_result
    
    def benchmark_naive_scheme(self, iterations: int = 100) -> BenchmarkResult:
        """
        测试朴素方案（仅RSU Token + 普通签名）
        
        Args:
            iterations: 迭代次数
        
        Returns:
            BenchmarkResult实例
        """
        self._log("开始朴素方案基准测试...")
        
        # 生成测试密钥对
        sk, pk = ed25519_generate_keypair()
        
        # 构造朴素方案的消息（仅包含基本信息，无零知识证明）
        message = b"naive_scheme_message_with_rsu_token_and_basic_data" * 5
        
        # 测试签名时间
        sign_times = []
        signature = None
        for _ in range(iterations):
            start = time.perf_counter()
            signature = ed25519_sign(sk, message)
            end = time.perf_counter()
            sign_times.append((end - start) * 1000)
        
        # 朴素方案的消息大小：RSU Token (64) + 签名 (64) + 基本数据 (约100)
        naive_message_size = 64 + 64 + 100
        
        sign_result = BenchmarkResult.from_measurements(
            operation="Naive_Scheme_Sign",
            times_ms=sign_times,
            size_bytes=naive_message_size,
            parameters={"scheme": "naive", "components": "RSU_Token + Ed25519"}
        )
        
        # 测试验证时间
        verify_times = []
        if signature:
            for _ in range(iterations):
                start = time.perf_counter()
                result = ed25519_verify(pk, message, signature)
                end = time.perf_counter()
                verify_times.append((end - start) * 1000)
        
        verify_result = BenchmarkResult.from_measurements(
            operation="Naive_Scheme_Verify",
            times_ms=verify_times,
            size_bytes=naive_message_size,
            parameters={"scheme": "naive", "components": "RSU_Token + Ed25519"}
        )
        
        self.results.add(sign_result)
        self.results.add(verify_result)
        
        self._log(f"  朴素方案签名: {sign_result.avg_time_ms:.4f} ms")
        self._log(f"  朴素方案验证: {verify_result.avg_time_ms:.4f} ms")
        self._log(f"  朴素方案消息大小: {naive_message_size} bytes")
        
        return sign_result
    
    def run_all(self, config: dict = None) -> BenchmarkResultCollection:
        """
        运行所有基准测试
        
        Args:
            config: 配置字典
        
        Returns:
            BenchmarkResultCollection实例
        """
        self._log("=" * 60)
        self._log("开始运行所有密码学基准测试")
        self._log("=" * 60)
        
        # 从配置中获取参数
        if config is None:
            config = {}
        
        iterations = config.get("benchmark_iterations", 100)
        ring_sizes = config.get("ring_sizes", [4, 8, 16])
        merkle_leaf_counts = config.get("merkle_leaf_counts", [10, 50, 100, 200])
        bulletproof_batch_sizes = config.get("bulletproof_batch_sizes", [1, 10, 100])
        
        # 运行各项测试
        self.benchmark_ed25519(iterations)
        self.benchmark_merkle_tree(merkle_leaf_counts)
        self.benchmark_bulletproofs(bulletproof_batch_sizes)
        self.benchmark_lsag(ring_sizes)
        self.benchmark_kyber(iterations)
        self.benchmark_naive_scheme(iterations)
        
        self._log("=" * 60)
        self._log("所有密码学基准测试完成")
        self._log(f"共完成 {len(self.results)} 项测试")
        self._log("=" * 60)
        
        return self.results
    
    def save_results(self, output_path: Path) -> None:
        """
        保存测试结果
        
        Args:
            output_path: 输出文件路径
        """
        self.results.to_json(output_path)
        self._log(f"测试结果已保存到: {output_path}")
