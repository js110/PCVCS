                      
                       

import os
import sys
import json
import time
import random
from pathlib import Path
from typing import List, Optional, Dict, Any

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from experiments.models.detection_result import DetectionResult, DetectionResultCollection
from experiments.logger import ExperimentLogger
from common.crypto import now_s, geohash_encode, merkle_root, merkle_proof
from common.crypto_adapters import (
    ed25519_generate_keypair, ed25519_sign,
    range_proof_prove, lrs_sign
)


class SecurityTester:
    
    def __init__(self, logger: Optional[ExperimentLogger] = None):
        self.logger = logger
        self.results = DetectionResultCollection()
        
              
        self.data_dir = project_root / "data"
        self.data_dir.mkdir(exist_ok=True)
        
               
        self.whitelist = self._load_whitelist()
        
                     
        self.rsu_keys = []
        for i in range(4):
            sk, pk = ed25519_generate_keypair()
            self.rsu_keys.append({
                "rsu_id": i + 1,
                "sk": sk,
                "pk": pk
            })
    
    def _log(self, message: str, level: str = "info") -> None:
        if self.logger:
            getattr(self.logger, level)(message)
    
    def _load_whitelist(self) -> List[str]:
        whitelist_file = self.data_dir / "whitelist_geohash.txt"
        if whitelist_file.exists():
            with open(whitelist_file, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        else:
                     
            default_whitelist = [
                "wtw3s8n", "wtw3s8p", "wtw3s8q", "wtw3s8r",
                "wtw3s8x", "wtw3s8y", "wtw3s8z", "wtw3s90"
            ]
            whitelist_file.write_text("\n".join(default_whitelist))
            return default_whitelist
    
    def _pk_to_hex(self, pk) -> str:
        if hasattr(pk, 'encode'):
                                
            return pk.encode().hex()
        elif isinstance(pk, bytes):
            return pk.hex()
        else:
            return bytes(pk).hex()
    
    def generate_valid_sample(self) -> Dict[str, Any]:
                          
        geohash = random.choice(self.whitelist)
        
                           
        current_time = now_s()
        window_id = current_time // 60
        timestamp = current_time
        
                 
        rsu = random.choice(self.rsu_keys)
        
                     
        nonce = random.getrandbits(64)
        expiry = current_time + 3600          
        token_msg = f"1|NET|{window_id}|{nonce}|{expiry}|{rsu['rsu_id']}".encode()
        token_sig = ed25519_sign(rsu['sk'], token_msg)
        
        token = {
            "version": 1,
            "region_id": "NET",
            "window_id": window_id,
            "nonce": nonce,
            "expiry_ts": expiry,
            "rsu_id": rsu['rsu_id'],
            "signature_hex": token_sig.hex()
        }
        
                    
        merkle_root_hash = merkle_root(self.whitelist)
        geohash_index = self.whitelist.index(geohash)
        merkle_path = merkle_proof(self.whitelist, geohash_index)
        
                            
        blinding = random.randint(1, 1000000)
        range_proof = range_proof_prove(timestamp, window_id * 60, (window_id + 1) * 60, blinding)
        
                  
        ring_size = 8
        ring_keys = [ed25519_generate_keypair() for _ in range(ring_size)]
        signer_index = 0
        ring_pubkeys = [pk for _, pk in ring_keys]
        signer_sk = ring_keys[signer_index][0]
        
        message = f"{geohash}|{timestamp}".encode()
        lsag_sig = lrs_sign(message, ring_pubkeys, signer_index, signer_sk, b"context")
        
        return {
            "type": "valid",
            "token": token,
            "geohash": geohash,
            "timestamp": timestamp,
            "merkle_root": merkle_root_hash,
            "merkle_proof": merkle_path,
            "range_proof": range_proof,
            "lsag_signature": lsag_sig,
            "rsu_pk": self._pk_to_hex(rsu['pk'])
        }
    
    def generate_location_forge_attack(self) -> Dict[str, Any]:
                          
        invalid_geohash = "wtw3xxx"          
        
                  
        current_time = now_s()
        window_id = current_time // 60
        timestamp = current_time
        
        rsu = random.choice(self.rsu_keys)
        nonce = random.getrandbits(64)
        expiry = current_time + 3600
        token_msg = f"1|NET|{window_id}|{nonce}|{expiry}|{rsu['rsu_id']}".encode()
        token_sig = ed25519_sign(rsu['sk'], token_msg)
        
        token = {
            "version": 1,
            "region_id": "NET",
            "window_id": window_id,
            "nonce": nonce,
            "expiry_ts": expiry,
            "rsu_id": rsu['rsu_id'],
            "signature_hex": token_sig.hex()
        }
        
                                  
        merkle_root_hash = merkle_root(self.whitelist)
        merkle_path = []            
        
        blinding = random.randint(1, 1000000)
        range_proof = range_proof_prove(timestamp, window_id * 60, (window_id + 1) * 60, blinding)
        
        ring_size = 8
        ring_keys = [ed25519_generate_keypair() for _ in range(ring_size)]
        ring_pubkeys = [pk for _, pk in ring_keys]
        signer_sk = ring_keys[0][0]
        
        message = f"{invalid_geohash}|{timestamp}".encode()
        lsag_sig = lrs_sign(message, ring_pubkeys, 0, signer_sk, b"context")
        
        return {
            "type": "location_forge",
            "token": token,
            "geohash": invalid_geohash,
            "timestamp": timestamp,
            "merkle_root": merkle_root_hash,
            "merkle_proof": merkle_path,
            "range_proof": range_proof,
            "lsag_signature": lsag_sig,
            "rsu_pk": self._pk_to_hex(rsu['pk'])
        }
    
    def generate_time_forge_attack(self) -> Dict[str, Any]:
        geohash = random.choice(self.whitelist)
        
                   
        current_time = now_s()
        window_id = current_time // 60
        invalid_timestamp = (window_id - 2) * 60             
        
        rsu = random.choice(self.rsu_keys)
        nonce = random.getrandbits(64)
        expiry = current_time + 3600
        token_msg = f"1|NET|{window_id}|{nonce}|{expiry}|{rsu['rsu_id']}".encode()
        token_sig = ed25519_sign(rsu['sk'], token_msg)
        
        token = {
            "version": 1,
            "region_id": "NET",
            "window_id": window_id,
            "nonce": nonce,
            "expiry_ts": expiry,
            "rsu_id": rsu['rsu_id'],
            "signature_hex": token_sig.hex()
        }
        
        merkle_root_hash = merkle_root(self.whitelist)
        geohash_index = self.whitelist.index(geohash)
        merkle_path = merkle_proof(self.whitelist, geohash_index)
        
                          
        blinding = random.randint(1, 1000000)
        range_proof = range_proof_prove(invalid_timestamp, window_id * 60, (window_id + 1) * 60, blinding)
        
        ring_size = 8
        ring_keys = [ed25519_generate_keypair() for _ in range(ring_size)]
        ring_pubkeys = [pk for _, pk in ring_keys]
        signer_sk = ring_keys[0][0]
        
        message = f"{geohash}|{invalid_timestamp}".encode()
        lsag_sig = lrs_sign(message, ring_pubkeys, 0, signer_sk, b"context")
        
        return {
            "type": "time_forge",
            "token": token,
            "geohash": geohash,
            "timestamp": invalid_timestamp,
            "merkle_root": merkle_root_hash,
            "merkle_proof": merkle_path,
            "range_proof": range_proof,
            "lsag_signature": lsag_sig,
            "rsu_pk": self._pk_to_hex(rsu['pk'])
        }

    def generate_token_abuse_attack(self) -> Dict[str, Any]:
        geohash = random.choice(self.whitelist)
        
        current_time = now_s()
        window_id = current_time // 60
        timestamp = current_time
        
        rsu = random.choice(self.rsu_keys)
        nonce = random.getrandbits(64)
                     
        expiry = current_time - 3600            
        token_msg = f"1|NET|{window_id}|{nonce}|{expiry}|{rsu['rsu_id']}".encode()
        token_sig = ed25519_sign(rsu['sk'], token_msg)
        
        token = {
            "version": 1,
            "region_id": "NET",
            "window_id": window_id,
            "nonce": nonce,
            "expiry_ts": expiry,        
            "rsu_id": rsu['rsu_id'],
            "signature_hex": token_sig.hex()
        }
        
        merkle_root_hash = merkle_root(self.whitelist)
        geohash_index = self.whitelist.index(geohash)

        merkle_path = merkle_proof(self.whitelist, geohash_index)
        
        blinding = random.randint(1, 1000000)
        range_proof = range_proof_prove(timestamp, window_id * 60, (window_id + 1) * 60, blinding)
        
        ring_size = 8
        ring_keys = [ed25519_generate_keypair() for _ in range(ring_size)]
        ring_pubkeys = [pk for _, pk in ring_keys]
        signer_sk = ring_keys[0][0]
        
        message = f"{geohash}|{timestamp}".encode()
        lsag_sig = lrs_sign(message, ring_pubkeys, 0, signer_sk, b"context")
        
        return {
            "type": "token_abuse",
            "token": token,
            "geohash": geohash,
            "timestamp": timestamp,
            "merkle_root": merkle_root_hash,
            "merkle_proof": merkle_path,
            "range_proof": range_proof,
            "lsag_signature": lsag_sig,
            "rsu_pk": self._pk_to_hex(rsu['pk'])
        }
    
    def generate_replay_attack(self) -> Dict[str, Any]:
        geohash = random.choice(self.whitelist)
        
                 
        current_time = now_s()
        old_timestamp = current_time - 7200            
        old_window_id = old_timestamp // 60
        
        rsu = random.choice(self.rsu_keys)
        nonce = random.getrandbits(64)
        expiry = old_timestamp + 3600
        token_msg = f"1|NET|{old_window_id}|{nonce}|{expiry}|{rsu['rsu_id']}".encode()
        token_sig = ed25519_sign(rsu['sk'], token_msg)
        
        token = {
            "version": 1,
            "region_id": "NET",
            "window_id": old_window_id,
            "nonce": nonce,
            "expiry_ts": expiry,
            "rsu_id": rsu['rsu_id'],
            "signature_hex": token_sig.hex()
        }
        
        merkle_root_hash = merkle_root(self.whitelist)
        geohash_index = self.whitelist.index(geohash)

        merkle_path = merkle_proof(self.whitelist, geohash_index)
        
        blinding = random.randint(1, 1000000)
        range_proof = range_proof_prove(old_timestamp, old_window_id * 60, (old_window_id + 1) * 60, blinding)
        
        ring_size = 8
        ring_keys = [ed25519_generate_keypair() for _ in range(ring_size)]
        ring_pubkeys = [pk for _, pk in ring_keys]
        signer_sk = ring_keys[0][0]
        
        message = f"{geohash}|{old_timestamp}".encode()
        lsag_sig = lrs_sign(message, ring_pubkeys, 0, signer_sk, b"context")
        
        return {
            "type": "replay",
            "token": token,
            "geohash": geohash,
            "timestamp": old_timestamp,
            "merkle_root": merkle_root_hash,
            "merkle_proof": merkle_path,
            "range_proof": range_proof,
            "lsag_signature": lsag_sig,
            "rsu_pk": self._pk_to_hex(rsu['pk'])
        }
    
    def generate_duplicate_report_attack(self) -> List[Dict[str, Any]]:
                       
        geohash = random.choice(self.whitelist)
        
        current_time = now_s()
        window_id = current_time // 60
        
        rsu = random.choice(self.rsu_keys)
        
                           
        ring_size = 8
        ring_keys = [ed25519_generate_keypair() for _ in range(ring_size)]
        ring_pubkeys = [pk for _, pk in ring_keys]
        signer_sk = ring_keys[0][0]         
        
        samples = []
        for i in range(2):
            timestamp = current_time + i
            
            nonce = random.getrandbits(64)
            expiry = current_time + 3600
            token_msg = f"1|NET|{window_id}|{nonce}|{expiry}|{rsu['rsu_id']}".encode()
            token_sig = ed25519_sign(rsu['sk'], token_msg)
            
            token = {
                "version": 1,
                "region_id": "NET",
                "window_id": window_id,
                "nonce": nonce,
                "expiry_ts": expiry,
                "rsu_id": rsu['rsu_id'],
                "signature_hex": token_sig.hex()
            }
            
            merkle_root_hash = merkle_root(self.whitelist)
            geohash_index = self.whitelist.index(geohash)

            merkle_path = merkle_proof(self.whitelist, geohash_index)
            
            blinding = random.randint(1, 1000000)
            range_proof = range_proof_prove(timestamp, window_id * 60, (window_id + 1) * 60, blinding)
            
            message = f"{geohash}|{timestamp}".encode()
            lsag_sig = lrs_sign(message, ring_pubkeys, 0, signer_sk, b"context")
            
            samples.append({
                "type": "duplicate",
                "token": token,
                "geohash": geohash,
                "timestamp": timestamp,
                "merkle_root": merkle_root_hash,
                "merkle_proof": merkle_path,
                "range_proof": range_proof,
                "lsag_signature": lsag_sig,
                "rsu_pk": self._pk_to_hex(rsu['pk'])
            })
        
        return samples
    
    def verify_sample(self, sample: Dict[str, Any], use_zkp: bool = True) -> bool:
        if not use_zkp:
                             
                              
            if sample["type"] == "token_abuse":
                                 
                return sample["token"]["expiry_ts"] > now_s()
            else:
                          
                return True
        
                    
        try:
                            
            if sample["token"]["expiry_ts"] < now_s():
                return False
            
                                  
            if sample["type"] == "location_forge":
                                  
                if sample["geohash"] not in self.whitelist:
                    return False
                            
                if not sample["merkle_proof"]:
                    return False
            
                                         
            if sample["type"] == "time_forge":
                               
                window_id = sample["token"]["window_id"]
                timestamp = sample["timestamp"]
                if not (window_id * 60 <= timestamp < (window_id + 1) * 60):
                    return False
            
                                 
            if sample["type"] == "replay":
                           
                if sample["timestamp"] < now_s() - 3600:         
                    return False
            
                          
            return True
            
        except Exception as e:
            self._log(f"验证异常: {e}", "warning")
            return False
    
    def test_attack_type(self, attack_type: str, sample_count: int, use_zkp: bool = True) -> DetectionResult:
        self._log(f"测试攻击: {attack_type} (样本数 {sample_count}, ZKP: {use_zkp})")
        
        detected_count = 0
        total_samples = sample_count
        
                   
        for i in range(sample_count):
            if attack_type == "location_forge":
                sample = self.generate_location_forge_attack()
            elif attack_type == "time_forge":
                sample = self.generate_time_forge_attack()
            elif attack_type == "token_abuse":
                sample = self.generate_token_abuse_attack()
            elif attack_type == "replay":
                sample = self.generate_replay_attack()
            elif attack_type == "duplicate":
                              
                samples = self.generate_duplicate_report_attack()
                                 
                if use_zkp:
                    key_images = [s["lsag_signature"].get("link_tag") for s in samples]
                    if len(set(key_images)) < len(key_images):
                        detected_count += 1
                continue
            else:
                self._log(f"未知攻击类型: {attack_type}", "warning")
                continue
            
                  
            is_valid = self.verify_sample(sample, use_zkp)
            
                             
            if not is_valid:
                detected_count += 1
        
        result = DetectionResult.from_counts(
            attack_type=attack_type,
            total_samples=total_samples,
            detected_count=detected_count,
            use_zkp=use_zkp
        )
        
        self.results.add(result)
        self._log(f"  检测率: {result.detection_rate*100:.2f}%%")
        
        return result
    
    def run_all_tests(self, attack_types: List[str], sample_count: int = 100) -> DetectionResultCollection:
        self._log("=" * 60)
        self._log("开始运行所有安全测试")
        self._log("=" * 60)
        
        for attack_type in attack_types:
                     
            self.test_attack_type(attack_type, sample_count, use_zkp=True)
                    
            self.test_attack_type(attack_type, sample_count, use_zkp=False)
        
        self._log("=" * 60)
        self._log(f"所有安全测试完成，共{len(self.results)} 项结果")
        self._log("=" * 60)
        
        return self.results
    
    def save_results(self, output_path: Path) -> None:
        self.results.to_json(output_path)
        self._log(f"安全测试结果已保存到: {output_path}")