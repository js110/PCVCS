                      
                       

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict


@dataclass
class DetectionResult:
    attack_type: str        
    total_samples: int        
    detected_count: int          
    detection_rate: float       
    false_positive_count: int = 0        
    false_negative_count: int = 0        
    use_zkp: bool = True             
    
    @classmethod
    def from_counts(cls, attack_type: str, total_samples: int, detected_count: int,
                   false_positive_count: int = 0, false_negative_count: int = 0,
                   use_zkp: bool = True) -> 'DetectionResult':
        detection_rate = detected_count / total_samples if total_samples > 0 else 0.0
        return cls(
            attack_type=attack_type,
            total_samples=total_samples,
            detected_count=detected_count,
            detection_rate=detection_rate,
            false_positive_count=false_positive_count,
            false_negative_count=false_negative_count,
            use_zkp=use_zkp
        )
    
    def get_false_positive_rate(self) -> float:
        if self.total_samples == 0:
            return 0.0
        return self.false_positive_count / self.total_samples
    
    def get_false_negative_rate(self) -> float:
        if self.total_samples == 0:
            return 0.0
        return self.false_negative_count / self.total_samples
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DetectionResult':
        return cls(**data)
    
    def to_json(self, json_path: Path) -> None:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
    
    @classmethod
    def from_json(cls, json_path: Path) -> 'DetectionResult':
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    def get_summary(self) -> str:
        summary = f"检测结果 - {self.attack_type}:\n"
        summary += f"  使用ZKP: {'是' if self.use_zkp else '否'}\n"
        summary += f"  总样本数: {self.total_samples}\n"
        summary += f"  检测数量: {self.detected_count}\n"
        summary += f"  检测率: {self.detection_rate*100:.2f}%\n"
        summary += f"  误报数量: {self.false_positive_count}\n"
        summary += f"  误报率: {self.get_false_positive_rate()*100:.2f}%\n"
        summary += f"  漏报数量: {self.false_negative_count}\n"
        summary += f"  漏报率: {self.get_false_negative_rate()*100:.2f}%\n"
        return summary
    
    def __str__(self) -> str:
        return self.get_summary()


class DetectionResultCollection:
    
    def __init__(self):
        self.results: List[DetectionResult] = []
    
    def add(self, result: DetectionResult) -> None:
        self.results.append(result)
    
    def get_by_attack_type(self, attack_type: str) -> List[DetectionResult]:
        return [r for r in self.results if r.attack_type == attack_type]
    
    def get_zkp_results(self) -> List[DetectionResult]:
        return [r for r in self.results if r.use_zkp]
    
    def get_naive_results(self) -> List[DetectionResult]:
        return [r for r in self.results if not r.use_zkp]
    
    def get_average_detection_rate(self, use_zkp: Optional[bool] = None) -> float:
        if use_zkp is None:
            results = self.results
        else:
            results = [r for r in self.results if r.use_zkp == use_zkp]
        
        if not results:
            return 0.0
        
        return sum(r.detection_rate for r in results) / len(results)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "results": [r.to_dict() for r in self.results],
            "count": len(self.results),
            "avg_detection_rate_zkp": self.get_average_detection_rate(use_zkp=True),
            "avg_detection_rate_naive": self.get_average_detection_rate(use_zkp=False)
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DetectionResultCollection':
        collection = cls()
        for result_data in data.get("results", []):
            collection.add(DetectionResult.from_dict(result_data))
        return collection
    
    def to_json(self, json_path: Path) -> None:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
    
    @classmethod
    def from_json(cls, json_path: Path) -> 'DetectionResultCollection':
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    def get_summary(self) -> str:
        summary = f"检测结果集合 ({len(self.results)} 项):\n"
        summary += "=" * 60 + "\n"
        for result in self.results:
            summary += result.get_summary() + "\n"
        summary += f"\n平均检测率 (ZKP): {self.get_average_detection_rate(use_zkp=True)*100:.2f}%\n"
        summary += f"平均检测率 (朴素): {self.get_average_detection_rate(use_zkp=False)*100:.2f}%\n"
        return summary
    
    def __len__(self) -> int:
        return len(self.results)
    
    def __iter__(self):
        return iter(self.results)
    
    def __str__(self) -> str:
        return self.get_summary()
