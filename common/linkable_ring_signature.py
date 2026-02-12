                      
                       

import os
import hashlib
import secrets
import json
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict


@dataclass
class VehicleIdentity:
    vehicle_id: str                  
    master_sk: bytes                    
    master_pk: bytes              
    registration_time: int          


@dataclass
class TaskKey:
    task_id: str                        
    derived_sk: bytes                    
    derived_pk: bytes                
    link_tag: str                   


@dataclass
class PublicKeyRing:
    ring_id: str                         
    task_id: str                             
    registered_pubkeys: List[bytes]          
    creation_time: int                    


@dataclass
class AuditRecord:
    vehicle_id: str                 
    master_pk: bytes             
    task_id: str                 
    derived_pk: bytes            
    link_tag: str               
    timestamp: int              


class LinkableRingSignature:
    
    def __init__(self, audit_authority_sk: Optional[bytes] = None):
        self.audit_authority_sk = audit_authority_sk or secrets.token_bytes(32)
        self.audit_authority_pk = hashlib.sha256(self.audit_authority_sk).digest()
        
                               
        self.audit_db: Dict[str, AuditRecord] = {}
        
                           
        self.link_tag_db: Dict[str, List[Dict[str, Any]]] = {}
        
                                                     
    
    def register_vehicle(self, vehicle_id: str) -> VehicleIdentity:
                
        master_sk = secrets.token_bytes(32)
        master_pk = hashlib.sha256(b"master_pk" + master_sk).digest()
        
        identity = VehicleIdentity(
            vehicle_id=vehicle_id,
            master_sk=master_sk,
            master_pk=master_pk,
            registration_time=int(os.times().system)
        )
        
        return identity
    
    def derive_task_key(self, vehicle_identity: VehicleIdentity, task_id: str) -> TaskKey:
                      
        master_sk = vehicle_identity.master_sk
        task_id_bytes = task_id.encode('utf-8')
        
               
        info = b"task_key_derivation"
        salt = hashlib.sha256(task_id_bytes).digest()
        
                      
        prk = hmac_sha256(salt, master_sk)
        
                     
        derived_sk = hmac_sha256(prk, info + b"\x01")[:32]
        
                 
        derived_pk = hashlib.sha256(b"derived_pk" + derived_sk).digest()
        
                   
                                             
        link_tag = hashlib.sha256(derived_sk + task_id_bytes).hexdigest()
        
        task_key = TaskKey(
            task_id=task_id,
            derived_sk=derived_sk,
            derived_pk=derived_pk,
            link_tag=link_tag
        )
        
                                 
        self._register_to_audit(vehicle_identity, task_key)
        
        return task_key
    
    def create_public_key_ring(self, task_id: str, registered_vehicles: List[VehicleIdentity]) -> PublicKeyRing:
                     
        pubkeys = []
        for vehicle in registered_vehicles:
            task_key = self.derive_task_key(vehicle, task_id)
            pubkeys.append(task_key.derived_pk)
        
        ring = PublicKeyRing(
            ring_id=hashlib.sha256((task_id + str(len(pubkeys))).encode()).hexdigest()[:16],
            task_id=task_id,
            registered_pubkeys=pubkeys,
            creation_time=int(os.times().system)
        )
        
        return ring
    
    def sign_message(
        self, 
        message: bytes, 
        task_key: TaskKey, 
        public_ring: PublicKeyRing
    ) -> Dict[str, Any]:
        from .crypto_adapters import lrs_sign
        
                     
        try:
            signer_index = public_ring.registered_pubkeys.index(task_key.derived_pk)
        except ValueError:
            raise ValueError("签名者公钥不在注册环中")
        
                  
        ctx = public_ring.task_id.encode('utf-8')
        
                   
        lrs_obj = lrs_sign(
            message=message,
            ring_pubkeys=public_ring.registered_pubkeys,
            signer_index=signer_index,
            sk_signer=task_key.derived_sk,
            ctx=ctx
        )
        
                        
        sigma_lrs = {
            "ring_id": public_ring.ring_id,
            "task_id": public_ring.task_id,
            "signature": lrs_obj["sig"],
            "link_tag": lrs_obj["link_tag"],           
            "context": lrs_obj["ctx"],
            "ring_size": len(public_ring.registered_pubkeys),
            "backend": lrs_obj.get("backend", "unknown")
        }
        
        return sigma_lrs
    
                                                     
    
    def verify_signature(
        self, 
        message: bytes, 
        sigma_lrs: Dict[str, Any], 
        public_ring: PublicKeyRing
    ) -> bool:
        from .crypto_adapters import lrs_verify
        
                  
        if sigma_lrs["task_id"] != public_ring.task_id:
            return False
        
                 
        lrs_obj = {
            "sig": sigma_lrs["signature"],
            "link_tag": sigma_lrs["link_tag"],
            "ctx": sigma_lrs["context"],
            "ring": [pk.hex() for pk in public_ring.registered_pubkeys]
        }
        
              
        return lrs_verify(message, lrs_obj, public_ring.registered_pubkeys)
    
    def detect_duplicate_submission(
        self, 
        sigma_lrs: Dict[str, Any], 
        task_id: str
    ) -> Tuple[bool, Optional[List[Dict[str, Any]]]]:
        link_tag = sigma_lrs["link_tag"]
        
                              
        task_key = f"{task_id}:{link_tag}"
        
        if task_key in self.link_tag_db:
                    
            previous = self.link_tag_db[task_key]
            return True, previous
        else:
                             
            submission_record = {
                "task_id": task_id,
                "link_tag": link_tag,
                "timestamp": int(os.times().system),
                "ring_id": sigma_lrs.get("ring_id", "unknown")
            }
            self.link_tag_db[task_key] = [submission_record]
            return False, None
    
                                                      
    
    def _register_to_audit(self, vehicle_identity: VehicleIdentity, task_key: TaskKey):
        record_key = f"{task_key.task_id}:{task_key.link_tag}"
        
        record = AuditRecord(
            vehicle_id=vehicle_identity.vehicle_id,
            master_pk=vehicle_identity.master_pk,
            task_id=task_key.task_id,
            derived_pk=task_key.derived_pk,
            link_tag=task_key.link_tag,
            timestamp=int(os.times().system)
        )
        
        self.audit_db[record_key] = record
    
    def controlled_deanonymization(
        self, 
        link_tag: str, 
        task_id: str, 
        authority_sk: bytes
    ) -> Optional[AuditRecord]:
                  
        if authority_sk != self.audit_authority_sk:
            raise PermissionError("无效的审计机构追踪密钥")
        
                
        record_key = f"{task_id}:{link_tag}"
        
        if record_key in self.audit_db:
            return self.audit_db[record_key]
        else:
            return None
    
    def export_audit_report(self, task_id: str, authority_sk: bytes) -> Dict[str, Any]:
        if authority_sk != self.audit_authority_sk:
            raise PermissionError("无效的审计机构追踪密钥")
        
                    
        task_records = [
            asdict(record) for key, record in self.audit_db.items()
            if record.task_id == task_id
        ]
        
              
        unique_vehicles = set(r["vehicle_id"] for r in task_records)
        
        report = {
            "task_id": task_id,
            "total_registered_vehicles": len(task_records),
            "unique_vehicles": len(unique_vehicles),
            "records": task_records,
            "timestamp": int(os.times().system)
        }
        
        return report


                                                

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    import hmac
    return hmac.new(key, data, hashlib.sha256).digest()


                                                

def example_usage():
    print("=== 可关联环签名（LRS）系统演示 ===\n")
    
              
    lrs_system = LinkableRingSignature()
    print(f"✓ 审计机构已初始化，追踪公钥: {lrs_system.audit_authority_pk.hex()[:16]}...\n")
    
             
    print("--- 车辆注册阶段 ---")
    vehicles = []
    for i in range(5):
        vehicle = lrs_system.register_vehicle(f"Vehicle_{i+1}")
        vehicles.append(vehicle)
        print(f"✓ 车辆 {vehicle.vehicle_id} 已注册，主公钥: {vehicle.master_pk.hex()[:16]}...")
    
                 
    task_id = "task_20251124_window_001"
    print(f"\n--- 创建任务 {task_id} 的公钥环 ---")
    public_ring = lrs_system.create_public_key_ring(task_id, vehicles)
    print(f"✓ 公钥环 Rring 已创建，环ID: {public_ring.ring_id}, 环大小: {len(public_ring.registered_pubkeys)}")
    
               
    print(f"\n--- 车辆签名阶段 ---")
    signer = vehicles[2]                
    task_key = lrs_system.derive_task_key(signer, task_id)
    print(f"✓ {signer.vehicle_id} 派生任务密钥，link_tag: {task_key.link_tag[:16]}...")
    
                                      
    message = json.dumps({
        "tid": task_id,
        "Cm": "commitment_merkle",
        "Cg": "commitment_geohash",
        "Ct": "commitment_time",
        "Ctok": "commitment_token"
    }, separators=(',', ':')).encode()
    
    sigma_lrs = lrs_system.sign_message(message, task_key, public_ring)
    print(f"✓ 签名生成成功，link_tag: {sigma_lrs['link_tag'][:16]}..., 后端: {sigma_lrs['backend']}")
    
             
    print(f"\n--- 验证签名阶段 ---")
    is_valid = lrs_system.verify_signature(message, sigma_lrs, public_ring)
    print(f"✓ 签名验证结果: {'通过' if is_valid else '失败'}")
    
               
    print(f"\n--- 重复检测阶段 ---")
    is_dup, prev = lrs_system.detect_duplicate_submission(sigma_lrs, task_id)
    print(f"✓ 首次提交检测: {'重复' if is_dup else '首次'}")
    
                
    sigma_lrs_2 = lrs_system.sign_message(message, task_key, public_ring)
    is_dup_2, prev_2 = lrs_system.detect_duplicate_submission(sigma_lrs_2, task_id)
    print(f"✓ 二次提交检测: {'重复 ⚠️' if is_dup_2 else '首次'}")
    if is_dup_2:
        print(f"  之前提交记录: {len(prev_2)} 条")
    
                 
    print(f"\n--- 审计去匿名化阶段 ---")
    audit_record = lrs_system.controlled_deanonymization(
        link_tag=sigma_lrs["link_tag"],
        task_id=task_id,
        authority_sk=lrs_system.audit_authority_sk
    )
    
    if audit_record:
        print(f"✓ 去匿名化成功，真实车辆: {audit_record.vehicle_id}")
        print(f"  主公钥: {audit_record.master_pk.hex()[:16]}...")
        print(f"  任务公钥: {audit_record.derived_pk.hex()[:16]}...")
    
               
    print(f"\n--- 审计报告导出 ---")
    report = lrs_system.export_audit_report(task_id, lrs_system.audit_authority_sk)
    print(f"✓ 任务 {task_id} 审计报告:")
    print(f"  注册车辆总数: {report['total_registered_vehicles']}")
    print(f"  唯一车辆数: {report['unique_vehicles']}")
    
    print("\n=== 演示完成 ===")


if __name__ == "__main__":
    example_usage()
