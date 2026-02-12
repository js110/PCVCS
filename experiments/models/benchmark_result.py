                      
                       

import json
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class BenchmarkResult:
    
    operation: str                      
    avg_time_ms: float            
    std_time_ms: float = 0.0           
    min_time_ms: float = 0.0            
    max_time_ms: float = 0.0            
    size_bytes: int = 0          
    iterations: int = 1        
    parameters: Dict[str, Any] = field(default_factory=dict)        
    
    @classmethod
    def from_measurements(cls, operation: str, times_ms: List[float],
                         size_bytes: int = 0, parameters: Optional[Dict[str, Any]] = None) -> 'BenchmarkResult':
        times_array = np.array(times_ms)
        return cls(
            operation=operation,
            avg_time_ms=float(np.mean(times_array)),
            std_time_ms=float(np.std(times_array)),
            min_time_ms=float(np.min(times_array)),
            max_time_ms=float(np.max(times_array)),
            size_bytes=size_bytes,
            iterations=len(times_ms),
            parameters=parameters or {}
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BenchmarkResult':
        return cls(**data)
    
    def to_json(self, json_path: Path) -> None:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
    
    @classmethod
    def from_json(cls, json_path: Path) -> 'BenchmarkResult':
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    def get_summary(self) -> str:
        summary = f"{self.operation}:\n"
        summary += f"  平均时间: {self.avg_time_ms:.4f} ms\n"
        summary += f"  标准差: {self.std_time_ms:.4f} ms\n"
        summary += f"  范围: [{self.min_time_ms:.4f}, {self.max_time_ms:.4f}] ms\n"
        if self.size_bytes > 0:
            summary += f"  大小: {self.size_bytes} bytes\n"
        summary += f"  迭代次数: {self.iterations}\n"
        if self.parameters:
            summary += f"  参数: {self.parameters}\n"
        return summary
    
    def __str__(self) -> str:
        return self.get_summary()


class BenchmarkResultCollection:
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
    
    def add(self, result: BenchmarkResult) -> None:
        self.results.append(result)
    
    def get_by_operation(self, operation: str) -> Optional[BenchmarkResult]:
        for result in self.results:
            if result.operation == operation:
                return result
        return None
    
    def get_by_parameter(self, param_name: str, param_value: Any) -> List[BenchmarkResult]:
        return [r for r in self.results 
                if param_name in r.parameters and r.parameters[param_name] == param_value]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "results": [r.to_dict() for r in self.results],
            "count": len(self.results)
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BenchmarkResultCollection':
        collection = cls()
        for result_data in data.get("results", []):
            collection.add(BenchmarkResult.from_dict(result_data))
        return collection
    
    def to_json(self, json_path: Path) -> None:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
    
    @classmethod
    def from_json(cls, json_path: Path) -> 'BenchmarkResultCollection':
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    def get_summary(self) -> str:
        summary = f"基准测试结果集合 ({len(self.results)} 项):\n"
        summary += "=" * 60 + "\n"
        for result in self.results:
            summary += result.get_summary() + "\n"
        return summary
    
    def __len__(self) -> int:
        return len(self.results)
    
    def __iter__(self):
        return iter(self.results)
    
    def __str__(self) -> str:
        return self.get_summary()
