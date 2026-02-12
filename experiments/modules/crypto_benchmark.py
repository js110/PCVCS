                      

                       

"""

密码学原语基准测试模块

"""



import os

import sys

import time

from pathlib import Path

from typing import List, Optional



        

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

        

                 

        sk, pk = ed25519_generate_keypair()

        

              

        message = b"test message for Ed25519 signature benchmark" * 10

        

                

        sign_times = []

        signature = None

        for i in range(iterations):

            start = time.perf_counter()

            signature = ed25519_sign(sk, message)

            end = time.perf_counter()

            sign_times.append((end - start) * 1000)         

        

        sign_result = BenchmarkResult.from_measurements(

            operation="Ed25519_Sign",

            times_ms=sign_times,

            size_bytes=len(signature) if signature else 64,

            parameters={"message_size": len(message)}

        )

        

                

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

            

                      

            leaves = [f"leaf_{i}" for i in range(leaf_count)]

            

                     

            root_times = []

            for _ in range(50):                       

                start = time.perf_counter()

                root = merkle_root(leaves)

                end = time.perf_counter()

                root_times.append((end - start) * 1000)

            

            root_result = BenchmarkResult.from_measurements(

                operation=f"Merkle_Root_Gen",

                times_ms=root_times,

                size_bytes=len(root) // 2 if root else 32,                       

                parameters={"leaf_count": leaf_count}

            )

            

                         

            root = merkle_root(leaves)

            test_leaf_index = 0              

            

            proof_gen_times = []

            proof_size = 0

            for _ in range(50):

                start = time.perf_counter()

                proof = merkle_proof(leaves, test_leaf_index)

                end = time.perf_counter()

                proof_gen_times.append((end - start) * 1000)

                if proof:

                                       

                    proof_size = len(proof) * 32 + 32                   

            

            proof_gen_result = BenchmarkResult.from_measurements(

                operation=f"Merkle_Proof_Gen",

                times_ms=proof_gen_times,

                size_bytes=proof_size,

                parameters={"leaf_count": leaf_count}

            )

            

                      

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

            

                  

            value = 1234567890

            lower_bound = 0

            upper_bound = 2**32 - 1

            blinding = 42

            

                      

            prove_times = []

            proof_size = 0

            for _ in range(batch_size):

                start = time.perf_counter()

                proof = range_proof_prove(value, lower_bound, upper_bound, blinding)

                end = time.perf_counter()

                prove_times.append((end - start) * 1000)

                if proof:

                            

                    import json

                    proof_size = len(json.dumps(proof).encode())

            

            prove_result = BenchmarkResult.from_measurements(

                operation=f"Bulletproofs_Prove",

                times_ms=prove_times,

                size_bytes=proof_size,

                parameters={"batch_size": batch_size, "range": f"[{lower_bound}, {upper_bound}]"}

            )

            

                      

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

            

                      

            ring_keys = []

            for _ in range(ring_size):

                sk, pk = ed25519_generate_keypair()

                ring_keys.append((sk, pk))

            

                          

            signer_sk, signer_pk = ring_keys[0]

            ring_pubkeys = [pk for _, pk in ring_keys]

            

                  

            message = b"test message for LSAG ring signature"

            context = b"test_context"

            

                      

            sign_times = []

            signature = None

            for _ in range(50):                 

                start = time.perf_counter()

                signature = lrs_sign(message, ring_pubkeys, 0, signer_sk, context)

                end = time.perf_counter()

                sign_times.append((end - start) * 1000)

            

                    

            import json

            sig_size = len(json.dumps(signature).encode()) if signature else 0

            

            sign_result = BenchmarkResult.from_measurements(

                operation=f"LSAG_Sign",

                times_ms=sign_times,

                size_bytes=sig_size,

                parameters={"ring_size": ring_size}

            )

            

                      

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

                             

            from common.kem_layer import kem_keygen, kem_encaps, kem_decaps

            

                    

            keygen_times = []

            for _ in range(iterations):

                start = time.perf_counter()

                pk, sk = kem_keygen()

                end = time.perf_counter()

                keygen_times.append((end - start) * 1000)

            

            keygen_result = BenchmarkResult.from_measurements(

                operation="Kyber_KeyGen",

                times_ms=keygen_times,

                size_bytes=len(pk) if pk else 800,                    

                parameters={"algorithm": "Kyber512"}

            )

            

                  

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

                size_bytes=len(ct) if ct else 768,                    

                parameters={"algorithm": "Kyber512"}

            )

            

                   

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

                size_bytes=len(ss) if ss else 32,            

                parameters={"algorithm": "Kyber512"}

            )

            

            self.results.add(keygen_result)

            self.results.add(encaps_result)

            self.results.add(decaps_result)

            

                      

            total_time = keygen_result.avg_time_ms + encaps_result.avg_time_ms + decaps_result.avg_time_ms

            

            self._log(f"  密钥生成: {keygen_result.avg_time_ms:.4f} ms")

            self._log(f"  封装: {encaps_result.avg_time_ms:.4f} ms")

            self._log(f"  解封装: {decaps_result.avg_time_ms:.4f} ms")

            self._log(f"  完整握手: {total_time:.4f} ms")

            

            return keygen_result

            

        except ImportError:

            self._log("Kyber库不可用，使用占位符实现", "warning")

            

                     

            handshake_times = []

            for _ in range(iterations):

                start = time.perf_counter()

                          

                time.sleep(0.001)              

                end = time.perf_counter()

                handshake_times.append((end - start) * 1000)

            

            handshake_result = BenchmarkResult.from_measurements(

                operation="Kyber_Handshake_Placeholder",

                times_ms=handshake_times,

                size_bytes=1600,         

                parameters={"algorithm": "Kyber512", "note": "compat"}

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

        

                 

        sk, pk = ed25519_generate_keypair()

        

                                   

        message = b"naive_scheme_message_with_rsu_token_and_basic_data" * 5

        

                

        sign_times = []

        signature = None

        for _ in range(iterations):

            start = time.perf_counter()

            signature = ed25519_sign(sk, message)

            end = time.perf_counter()

            sign_times.append((end - start) * 1000)

        

                                                          

        naive_message_size = 64 + 64 + 100

        

        sign_result = BenchmarkResult.from_measurements(

            operation="Naive_Scheme_Sign",

            times_ms=sign_times,

            size_bytes=naive_message_size,

            parameters={"scheme": "naive", "components": "RSU_Token + Ed25519"}

        )

        

                

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

        

                  

        if config is None:

            config = {}

        

        iterations = config.get("benchmark_iterations", 100)

        ring_sizes = config.get("ring_sizes", [4, 8, 16])

        merkle_leaf_counts = config.get("merkle_leaf_counts", [10, 50, 100, 200])

        bulletproof_batch_sizes = config.get("bulletproof_batch_sizes", [1, 10, 100])

        

                

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

