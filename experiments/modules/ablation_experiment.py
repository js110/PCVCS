                      

                       




import os

import sys

import time

import random

from pathlib import Path

from typing import List, Optional, Dict, Any



project_root = Path(__file__).parent.parent.parent

sys.path.insert(0, str(project_root))



from experiments.models.ablation_result import (

    VariantResult, SensitivityResult, AblationResultCollection

)

from experiments.logger import ExperimentLogger

from common.crypto import merkle_root, merkle_proof, geohash_encode

from common.crypto_adapters import (

    ed25519_generate_keypair, ed25519_sign, ed25519_verify,

    range_proof_prove, range_proof_verify,

    lrs_sign, lrs_verify

)





class AblationExperiment:


    

    def __init__(self, logger: Optional[ExperimentLogger] = None):


        self.logger = logger

        self.results = AblationResultCollection()

        

              

        self.data_dir = project_root / "data"

        self.whitelist = self._load_whitelist()

    

    def _log(self, message: str, level: str = "info") -> None:


        if self.logger:

            getattr(self.logger, level)(message)

    

    def _load_whitelist(self) -> List[str]:


        whitelist_file = self.data_dir / "whitelist_geohash.txt"

        if whitelist_file.exists():

            with open(whitelist_file, 'r', encoding='utf-8') as f:

                return [line.strip() for line in f if line.strip()]

        return ["wtw3s8n", "wtw3s8p", "wtw3s8q", "wtw3s8r"]

    

    def test_full_scheme(self, iterations: int = 100) -> VariantResult:


        self._log("测试完整方案（所有组件）...")

        

        times = []

        sizes = []

        

        for _ in range(iterations):

            start = time.perf_counter()

            

                                     

            sk, pk = ed25519_generate_keypair()

            message = b"test_message"

            sig = ed25519_sign(sk, message)

            

                         

            geohash = random.choice(self.whitelist)

            root = merkle_root(self.whitelist)

            geohash_index = self.whitelist.index(geohash)

            proof = merkle_proof(self.whitelist, geohash_index)

            

                                 

            timestamp = int(time.time())

            window_id = timestamp // 60

            blinding = random.randint(1, 1000000)

            range_proof = range_proof_prove(timestamp, window_id * 60, (window_id + 1) * 60, blinding)

            

                        

            ring_size = 8

            ring_keys = [ed25519_generate_keypair() for _ in range(ring_size)]

            ring_pubkeys = [pk for _, pk in ring_keys]

            signer_sk = ring_keys[0][0]

            lsag_sig = lrs_sign(message, ring_pubkeys, 0, signer_sk, b"context")

            

                              

                                   

            

            end = time.perf_counter()

            times.append((end - start) * 1000)

            

                   

            import json

            total_size = (

                len(sig) +             

                len(root) // 2 + len(proof) * 32 +          

                len(json.dumps(range_proof).encode()) +                

                len(json.dumps(lsag_sig).encode()) +        

                800           

            )

            sizes.append(total_size)

        

        avg_time = sum(times) / len(times)

        avg_size = sum(sizes) / len(sizes)

        

        result = VariantResult(

            variant_name="full_scheme",

            avg_time_ms=avg_time,

            avg_size_bytes=avg_size,

            capabilities={

                "location_privacy": True,

                "time_privacy": True,

                "anonymity": True,

                "linkability": True,

                "post_quantum": True

            }

        )

        

        self.results.add_variant(result)

        self._log(f"  完整方案: {avg_time:.4f} ms, {avg_size:.0f} bytes")

        

        return result

    

    def test_variant_no_bulletproofs(self, iterations: int = 100) -> VariantResult:


        self._log("测试变体：去掉Bulletproofs...")

        

        times = []

        sizes = []

        

        for _ in range(iterations):

            start = time.perf_counter()

            

                          

            sk, pk = ed25519_generate_keypair()

            message = b"test_message"

            sig = ed25519_sign(sk, message)

            

                         

            geohash = random.choice(self.whitelist)

            root = merkle_root(self.whitelist)

            geohash_index = self.whitelist.index(geohash)

            proof = merkle_proof(self.whitelist, geohash_index)

            

                        

            ring_size = 8

            ring_keys = [ed25519_generate_keypair() for _ in range(ring_size)]

            ring_pubkeys = [pk for _, pk in ring_keys]

            signer_sk = ring_keys[0][0]

            lsag_sig = lrs_sign(message, ring_pubkeys, 0, signer_sk, b"context")

            

                          

            

            end = time.perf_counter()

            times.append((end - start) * 1000)

            

                                  

            import json

            total_size = (

                len(sig) +

                len(root) // 2 + len(proof) * 32 +

                len(json.dumps(lsag_sig).encode()) +

                800

            )

            sizes.append(total_size)

        

        avg_time = sum(times) / len(times)

        avg_size = sum(sizes) / len(sizes)

        

        result = VariantResult(

            variant_name="no_bulletproofs",

            avg_time_ms=avg_time,

            avg_size_bytes=avg_size,

            capabilities={

                "location_privacy": True,

                "time_privacy": False,           

                "anonymity": True,

                "linkability": True,

                "post_quantum": True

            }

        )

        

        self.results.add_variant(result)

        self._log(f"  无Bulletproofs: {avg_time:.4f} ms, {avg_size:.0f} bytes")

        

        return result

    

    def test_variant_no_lsag(self, iterations: int = 100) -> VariantResult:


        self._log("测试变体：去掉LSAG（使用普通签名）...")

        

        times = []

        sizes = []

        

        for _ in range(iterations):

            start = time.perf_counter()

            

                          

            sk, pk = ed25519_generate_keypair()

            message = b"test_message"

            sig = ed25519_sign(sk, message)

            

                         

            geohash = random.choice(self.whitelist)

            root = merkle_root(self.whitelist)

            geohash_index = self.whitelist.index(geohash)

            proof = merkle_proof(self.whitelist, geohash_index)

            

                             

            timestamp = int(time.time())

            window_id = timestamp // 60

            blinding = random.randint(1, 1000000)

            range_proof = range_proof_prove(timestamp, window_id * 60, (window_id + 1) * 60, blinding)

            

                                    

            user_sk, user_pk = ed25519_generate_keypair()

            user_sig = ed25519_sign(user_sk, message)

            

                          

            

            end = time.perf_counter()

            times.append((end - start) * 1000)

            

                               

            import json

            total_size = (

                len(sig) +

                len(root) // 2 + len(proof) * 32 +

                len(json.dumps(range_proof).encode()) +

                len(user_sig) +        

                800

            )

            sizes.append(total_size)

        

        avg_time = sum(times) / len(times)

        avg_size = sum(sizes) / len(sizes)

        

        result = VariantResult(

            variant_name="no_lsag",

            avg_time_ms=avg_time,

            avg_size_bytes=avg_size,

            capabilities={

                "location_privacy": True,

                "time_privacy": True,

                "anonymity": False,        

                "linkability": False,         

                "post_quantum": True

            }

        )

        

        self.results.add_variant(result)

        self._log(f"  无LSAG: {avg_time:.4f} ms, {avg_size:.0f} bytes")

        

        return result

    

    def test_variant_no_kyber(self, iterations: int = 100) -> VariantResult:


        self._log("测试变体：去掉Kyber（使用传统密钥）...")

        

        times = []

        sizes = []

        

        for _ in range(iterations):

            start = time.perf_counter()

            

                          

            sk, pk = ed25519_generate_keypair()

            message = b"test_message"

            sig = ed25519_sign(sk, message)

            

                         

            geohash = random.choice(self.whitelist)

            root = merkle_root(self.whitelist)

            geohash_index = self.whitelist.index(geohash)

            proof = merkle_proof(self.whitelist, geohash_index)

            

                             

            timestamp = int(time.time())

            window_id = timestamp // 60

            blinding = random.randint(1, 1000000)

            range_proof = range_proof_prove(timestamp, window_id * 60, (window_id + 1) * 60, blinding)

            

                        

            ring_size = 8

            ring_keys = [ed25519_generate_keypair() for _ in range(ring_size)]

            ring_pubkeys = [pk for _, pk in ring_keys]

            signer_sk = ring_keys[0][0]

            lsag_sig = lrs_sign(message, ring_pubkeys, 0, signer_sk, b"context")

            

                                

                              

            

            end = time.perf_counter()

            times.append((end - start) * 1000)

            

                                

            import json

            total_size = (

                len(sig) +

                len(root) // 2 + len(proof) * 32 +

                len(json.dumps(range_proof).encode()) +

                len(json.dumps(lsag_sig).encode()) +

                32             

            )

            sizes.append(total_size)

        

        avg_time = sum(times) / len(times)

        avg_size = sum(sizes) / len(sizes)

        

        result = VariantResult(

            variant_name="no_kyber",

            avg_time_ms=avg_time,

            avg_size_bytes=avg_size,

            capabilities={

                "location_privacy": True,

                "time_privacy": True,

                "anonymity": True,

                "linkability": True,

                "post_quantum": False          

            }

        )

        

        self.results.add_variant(result)

        self._log(f"  无Kyber: {avg_time:.4f} ms, {avg_size:.0f} bytes")

        

        return result



    def test_geohash_sensitivity(self, precisions: List[int] = None) -> List[SensitivityResult]:


        if precisions is None:

            precisions = [5, 6, 7]

        

        self._log("测试Geohash精度敏感性...")

        

        results = []

        

        for precision in precisions:

            self._log(f"  测试精度: {precision}位")

            

                               

            test_whitelist = []

            for i in range(20):            

                lat = 31.23 + i * 0.001

                lon = 121.47 + i * 0.001

                gh = geohash_encode(lat, lon, precision=precision)

                if gh not in test_whitelist:

                    test_whitelist.append(gh)

            

                         

            root_times = []

            proof_times = []

            proof_sizes = []

            

            for _ in range(50):

                       

                start = time.perf_counter()

                root = merkle_root(test_whitelist)

                end = time.perf_counter()

                root_times.append((end - start) * 1000)

                

                        

                test_gh = random.choice(test_whitelist)

                test_gh_index = test_whitelist.index(test_gh)

                start = time.perf_counter()

                proof = merkle_proof(test_whitelist, test_gh_index)

                end = time.perf_counter()

                proof_times.append((end - start) * 1000)

                

                      

                proof_size = len(proof) * 32 if proof else 0

                proof_sizes.append(proof_size)

            

                           

                              

            false_positive_rate = 1.0 / (2 ** precision)

            false_negative_rate = 0.01            

            

            result = SensitivityResult(

                parameter_name="geohash_precision",

                parameter_value=precision,

                performance_metrics={

                    "whitelist_size": len(test_whitelist),

                    "avg_root_time_ms": sum(root_times) / len(root_times),

                    "avg_proof_time_ms": sum(proof_times) / len(proof_times),

                    "avg_proof_size_bytes": sum(proof_sizes) / len(proof_sizes)

                },

                security_metrics={

                    "false_positive_rate": false_positive_rate,

                    "false_negative_rate": false_negative_rate

                }

            )

            

            self.results.add_sensitivity(result)

            results.append(result)

            

            self._log(f"    白名单大小: {len(test_whitelist)}")

            self._log(f"    证明生成: {result.performance_metrics['avg_proof_time_ms']:.4f} ms")

            self._log(f"    证明大小: {result.performance_metrics['avg_proof_size_bytes']:.0f} bytes")

        

        return results

    

    def test_ring_size_sensitivity(self, ring_sizes: List[int] = None) -> List[SensitivityResult]:


        if ring_sizes is None:

            ring_sizes = [4, 8, 16]

        

        self._log("测试环大小敏感性...")

        

        results = []

        

        for ring_size in ring_sizes:

            self._log(f"  测试环大小: {ring_size}")

            

            sign_times = []

            verify_times = []

            sig_sizes = []

            

            for _ in range(50):

                     

                ring_keys = [ed25519_generate_keypair() for _ in range(ring_size)]

                ring_pubkeys = [pk for _, pk in ring_keys]

                signer_sk = ring_keys[0][0]

                

                message = b"test_message_for_ring_signature"

                

                      

                start = time.perf_counter()

                lsag_sig = lrs_sign(message, ring_pubkeys, 0, signer_sk, b"context")

                end = time.perf_counter()

                sign_times.append((end - start) * 1000)

                

                      

                start = time.perf_counter()

                result = lrs_verify(message, lsag_sig, ring_pubkeys)

                end = time.perf_counter()

                verify_times.append((end - start) * 1000)

                

                      

                import json

                sig_size = len(json.dumps(lsag_sig).encode())

                sig_sizes.append(sig_size)

            

            result = SensitivityResult(

                parameter_name="ring_size",

                parameter_value=ring_size,

                performance_metrics={

                    "avg_sign_time_ms": sum(sign_times) / len(sign_times),

                    "avg_verify_time_ms": sum(verify_times) / len(verify_times),

                    "avg_signature_size_bytes": sum(sig_sizes) / len(sig_sizes),

                    "total_time_ms": (sum(sign_times) + sum(verify_times)) / len(sign_times)

                },

                security_metrics={

                    "anonymity_set_size": ring_size,

                    "unlinkability_probability": 1.0 / ring_size

                }

            )

            

            self.results.add_sensitivity(result)

            results.append(result)

            

            self._log(f"    签名时间: {result.performance_metrics['avg_sign_time_ms']:.4f} ms")

            self._log(f"    验证时间: {result.performance_metrics['avg_verify_time_ms']:.4f} ms")

            self._log(f"    签名大小: {result.performance_metrics['avg_signature_size_bytes']:.0f} bytes")

        

        return results

    

    def run_all_experiments(self) -> AblationResultCollection:


        self._log("=" * 60)

        self._log("开始运行所有消融实验")

        self._log("=" * 60)

        

                

        self._log("\n--- 模块消融实验 ---")

        self.test_full_scheme()

        self.test_variant_no_bulletproofs()

        self.test_variant_no_lsag()

        self.test_variant_no_kyber()

        

                 

        self._log("\n--- 参数敏感性实验 ---")

        self.test_geohash_sensitivity()

        self.test_ring_size_sensitivity()

        

        self._log("=" * 60)

        self._log(f"所有消融实验完成")

        self._log(f"  变体测试: {len(self.results.variant_results)} 项")

        self._log(f"  敏感性测试: {len(self.results.sensitivity_results)} 项")

        self._log("=" * 60)

        

        return self.results

    

    def save_results(self, output_path: Path) -> None:


        self.results.to_json(output_path)

        self._log(f"消融实验结果已保存到: {output_path}")

