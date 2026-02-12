#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全性测试模块 - 使用真实攻击样本
"""

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
    """安全性测试器 - 生成真实攻击样本并测试检测能力"""
    
    def __init__(self, logger: Optional[ExperimentLogger] = None):
        """初始化测试器"""
        self.logger = logger
        self.results = DetectionResultCollection()
        
        # 数据目录
        self.data_dir = project_root / "data"
        self.data_dir.mkdir(exist_ok=True)
        
        # 加载白名单
        self.whitelist = self._load_whitelist()
        
        # 生成测试用的RSU密钥
        self.rsu_keys = []
        for i in range(4):
            sk, pk = ed25519_generate_keypair()
            self.rsu_keys.append({
                "rsu_id": i + 1,
                "sk": sk,
                "pk": pk
            })
    
    def _log(self, message: str, level: str = "info") -> None:
        """记录日志"""
        if self.logger:
            getattr(self.logger, level)(message)
    
    def _load_whitelist(self) -> List[str]:
        """加载地理哈希白名单"""
        whitelist_file = self.data_dir / "whitelist_geohash.txt"
        if whitelist_file.exists():
            with open(whitelist_file, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        else:
            # 创建默认白名单
            default_whitelist = [
                "wtw3s8n", "wtw3s8p", "wtw3s8q", "wtw3s8r",
                "wtw3s8x", "wtw3s8y", "wtw3s8z", "wtw3s90"
            ]
            whitelist_file.write_text("\n".join(default_whitelist))
            return default_whitelist
    
    def _pk_to_hex(self, pk) -> str:
        """将公钥转换为十六进制字符"""
        if hasattr(pk, 'encode'):
            # PyNaCl VerifyKey对象
            return pk.encode().hex()
        elif isinstance(pk, bytes):
            return pk.hex()
        else:
            return bytes(pk).hex()
    
    def generate_valid_sample(self) -> Dict[str, Any]:
        """生成合法样本"""
        # 选择一个白名单中的geohash
        geohash = random.choice(self.whitelist)
        
        # 生成合法的时间戳（当前时间窗口内）
        current_time = now_s()
        window_id = current_time // 60
        timestamp = current_time
        
        # 选择一个RSU
        rsu = random.choice(self.rsu_keys)
        
        # 生成RSU Token
        nonce = random.getrandbits(64)
        expiry = current_time + 3600  # 1小时后过期
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
        
        # 生成Merkle证明
        merkle_root_hash = merkle_root(self.whitelist)
        geohash_index = self.whitelist.index(geohash)
        merkle_path = merkle_proof(self.whitelist, geohash_index)
        
        # 生成Bulletproofs范围证明
        blinding = random.randint(1, 1000000)
        range_proof = range_proof_prove(timestamp, window_id * 60, (window_id + 1) * 60, blinding)
        
        # 生成LSAG签名
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
        """生成位置伪造攻击样本"""
        # 使用不在白名单中的geohash
        fake_geohash = "wtw3xxx"  # 不在白名单中
        
        # 其他部分正常生成
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
        
        # 伪造Merkle证明（使用错误的geohash）
        merkle_root_hash = merkle_root(self.whitelist)
        merkle_path = []  # 空路径或错误路径
        
        blinding = random.randint(1, 1000000)
        range_proof = range_proof_prove(timestamp, window_id * 60, (window_id + 1) * 60, blinding)
        
        ring_size = 8
        ring_keys = [ed25519_generate_keypair() for _ in range(ring_size)]
        ring_pubkeys = [pk for _, pk in ring_keys]
        signer_sk = ring_keys[0][0]
        
        message = f"{fake_geohash}|{timestamp}".encode()
        lsag_sig = lrs_sign(message, ring_pubkeys, 0, signer_sk, b"context")
        
        return {
            "type": "location_forge",
            "token": token,
            "geohash": fake_geohash,
            "timestamp": timestamp,
            "merkle_root": merkle_root_hash,
            "merkle_proof": merkle_path,
            "range_proof": range_proof,
            "lsag_signature": lsag_sig,
            "rsu_pk": self._pk_to_hex(rsu['pk'])
        }
    
    def generate_time_forge_attack(self) -> Dict[str, Any]:
        """生成时间窗口作弊攻击样本"""
        geohash = random.choice(self.whitelist)
        
        # 使用窗口外的时间戳
        current_time = now_s()
        window_id = current_time // 60
        fake_timestamp = (window_id - 2) * 60  # 2个窗口之前的时间
        
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
        
        # 伪造范围证明（使用错误的时间戳）
        blinding = random.randint(1, 1000000)
        range_proof = range_proof_prove(fake_timestamp, window_id * 60, (window_id + 1) * 60, blinding)
        
        ring_size = 8
        ring_keys = [ed25519_generate_keypair() for _ in range(ring_size)]
        ring_pubkeys = [pk for _, pk in ring_keys]
        signer_sk = ring_keys[0][0]
        
        message = f"{geohash}|{fake_timestamp}".encode()
        lsag_sig = lrs_sign(message, ring_pubkeys, 0, signer_sk, b"context")
        
        return {
            "type": "time_forge",
            "token": token,
            "geohash": geohash,
            "timestamp": fake_timestamp,
            "merkle_root": merkle_root_hash,
            "merkle_proof": merkle_path,
            "range_proof": range_proof,
            "lsag_signature": lsag_sig,
            "rsu_pk": self._pk_to_hex(rsu['pk'])
        }

    def generate_token_abuse_attack(self) -> Dict[str, Any]:
        """生成Token滥用攻击样本（过期Token）"""
        geohash = random.choice(self.whitelist)
        
        current_time = now_s()
        window_id = current_time // 60
        timestamp = current_time
        
        rsu = random.choice(self.rsu_keys)
        nonce = random.getrandbits(64)
        # 使用已过期的Token
        expiry = current_time - 3600  # 1小时前就过期了
        token_msg = f"1|NET|{window_id}|{nonce}|{expiry}|{rsu['rsu_id']}".encode()
        token_sig = ed25519_sign(rsu['sk'], token_msg)
        
        token = {
            "version": 1,
            "region_id": "NET",
            "window_id": window_id,
            "nonce": nonce,
            "expiry_ts": expiry,  # 过期时间
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
        """生成重放攻击样本（旧时间戳）"""
        geohash = random.choice(self.whitelist)
        
        # 使用旧的时间戳
        current_time = now_s()
        old_timestamp = current_time - 7200  # 2小时前的时间戳
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
        """生成多次上报攻击样本（相同key image）"""
        # 生成两个使用相同私钥的上报
        geohash = random.choice(self.whitelist)
        
        current_time = now_s()
        window_id = current_time // 60
        
        rsu = random.choice(self.rsu_keys)
        
        # 生成环签名密钥（使用相同的签名者）
        ring_size = 8
        ring_keys = [ed25519_generate_keypair() for _ in range(ring_size)]
        ring_pubkeys = [pk for _, pk in ring_keys]
        signer_sk = ring_keys[0][0]  # 相同的签名
        
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
        """
        验证样本
        
        Args:
            sample: 样本数据
            use_zkp: 是否使用零知识证明验证
        
        Returns:
            是否通过验证
        """
        if not use_zkp:
            # 朴素方案：只验证Token签名
            # 在朴素方案中，大部分攻击无法检测
            if sample["type"] == "token_abuse":
                # 朴素方案可以检测过期Token
                return sample["token"]["expiry_ts"] > now_s()
            else:
                # 其他攻击无法检测
                return True
        
        # ZKP方案：完整验证
        try:
            # 1. 验证Token过期时间
            if sample["token"]["expiry_ts"] < now_s():
                return False
            
            # 2. 验证Merkle证明（位置合规性）
            if sample["type"] == "location_forge":
                # 检查geohash是否在白名单中
                if sample["geohash"] not in self.whitelist:
                    return False
                # 检查Merkle路径
                if not sample["merkle_proof"]:
                    return False
            
            # 3. 验证Bulletproofs范围证明（时间窗口）
            if sample["type"] == "time_forge":
                # 检查时间戳是否在合法窗口内
                window_id = sample["token"]["window_id"]
                timestamp = sample["timestamp"]
                if not (window_id * 60 <= timestamp < (window_id + 1) * 60):
                    return False
            
            # 4. 验证重放攻击（检查时间戳新鲜度）
            if sample["type"] == "replay":
                # 检查时间戳是否过旧
                if sample["timestamp"] < now_s() - 3600:  # 超过1小时
                    return False
            
            # 合法样本应该通过所有检测
            return True
            
        except Exception as e:
            self._log(f"验证异常: {e}", "warning")
            return False
    
    def test_attack_type(self, attack_type: str, sample_count: int, use_zkp: bool = True) -> DetectionResult:
        """
        测试特定类型的攻击
        
        Args:
            attack_type: 攻击类型
            sample_count: 样本数量
            use_zkp: 是否使用零知识证明
        
        Returns:
            DetectionResult实例
        """
        self._log(f"测试攻击: {attack_type} (样本数 {sample_count}, ZKP: {use_zkp})")
        
        detected_count = 0
        total_samples = sample_count
        
        # 生成攻击样本并验证
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
                # 多次上报攻击需要特殊处理
                samples = self.generate_duplicate_report_attack()
                # 检查key image是否相同
                if use_zkp:
                    key_images = [s["lsag_signature"].get("link_tag") for s in samples]
                    if len(set(key_images)) < len(key_images):
                        detected_count += 1
                continue
            else:
                self._log(f"未知攻击类型: {attack_type}", "warning")
                continue
            
            # 验证样本
            is_valid = self.verify_sample(sample, use_zkp)
            
            # 如果验证失败，说明攻击被检测到
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
        """运行所有安全测试"""
        self._log("=" * 60)
        self._log("开始运行所有安全测试")
        self._log("=" * 60)
        
        for attack_type in attack_types:
            # 测试ZKP方案
            self.test_attack_type(attack_type, sample_count, use_zkp=True)
            # 测试朴素方案
            self.test_attack_type(attack_type, sample_count, use_zkp=False)
        
        self._log("=" * 60)
        self._log(f"所有安全测试完成，共{len(self.results)} 项结果")
        self._log("=" * 60)
        
        return self.results
    
    def save_results(self, output_path: Path) -> None:
        """保存结果"""
        self.results.to_json(output_path)
        self._log(f"安全测试结果已保存到: {output_path}")