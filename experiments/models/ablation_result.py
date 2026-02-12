                      
                       
"""
消融实验结果数据模型
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class VariantResult:
    """方案变体结果数据结构"""
    variant_name: str        
    avg_time_ms: float              
    avg_size_bytes: float              
    capabilities: Dict[str, bool] = field(default_factory=dict)        
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VariantResult':
        """从字典创建实例"""
        return cls(**data)
    
    def to_json(self, json_path: Path) -> None:
        """保存为JSON文件"""
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
    
    @classmethod
    def from_json(cls, json_path: Path) -> 'VariantResult':
        """从JSON文件加载"""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    def get_capability_count(self) -> int:
        """获取具备的能力数量"""
        return sum(1 for v in self.capabilities.values() if v)
    
    def get_summary(self) -> str:
        """获取结果摘要"""
        summary = f"变体结果 - {self.variant_name}:\n"
        summary += f"  平均处理时间: {self.avg_time_ms:.4f} ms\n"
        summary += f"  平均消息大小: {self.avg_size_bytes:.0f} bytes\n"
        summary += f"  安全能力 ({self.get_capability_count()}/{len(self.capabilities)}):\n"
        for capability, enabled in self.capabilities.items():
            status = "✔" if enabled else "✘"
            summary += f"    {status} {capability}\n"
        return summary
    
    def __str__(self) -> str:
        return self.get_summary()


@dataclass
class SensitivityResult:
    """参数敏感性结果数据结构"""
    parameter_name: str        
    parameter_value: Any       
    performance_metrics: Dict[str, float] = field(default_factory=dict)        
    security_metrics: Dict[str, float] = field(default_factory=dict)        
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SensitivityResult':
        """从字典创建实例"""
        return cls(**data)
    
    def to_json(self, json_path: Path) -> None:
        """保存为JSON文件"""
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
    
    @classmethod
    def from_json(cls, json_path: Path) -> 'SensitivityResult':
        """从JSON文件加载"""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    def get_summary(self) -> str:
        """获取结果摘要"""
        summary = f"敏感性结果 - {self.parameter_name} = {self.parameter_value}:\n"
        if self.performance_metrics:
            summary += "  性能指标:\n"
            for metric, value in self.performance_metrics.items():
                summary += f"    {metric}: {value}\n"
        if self.security_metrics:
            summary += "  安全指标:\n"
            for metric, value in self.security_metrics.items():
                summary += f"    {metric}: {value}\n"
        return summary
    
    def __str__(self) -> str:
        return self.get_summary()


class AblationResultCollection:
    """消融实验结果集合"""
    
    def __init__(self):
        self.variant_results: List[VariantResult] = []
        self.sensitivity_results: List[SensitivityResult] = []
    
    def add_variant(self, result: VariantResult) -> None:
        """添加变体结果"""
        self.variant_results.append(result)
    
    def add_sensitivity(self, result: SensitivityResult) -> None:
        """添加敏感性结果"""
        self.sensitivity_results.append(result)
    
    def get_variant_by_name(self, variant_name: str) -> Optional[VariantResult]:
        """根据变体名称获取结果"""
        for result in self.variant_results:
            if result.variant_name == variant_name:
                return result
        return None
    
    def get_sensitivity_by_parameter(self, parameter_name: str) -> List[SensitivityResult]:
        """根据参数名称获取敏感性结果"""
        return [r for r in self.sensitivity_results if r.parameter_name == parameter_name]
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "variant_results": [r.to_dict() for r in self.variant_results],
            "sensitivity_results": [r.to_dict() for r in self.sensitivity_results],
            "variant_count": len(self.variant_results),
            "sensitivity_count": len(self.sensitivity_results)
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AblationResultCollection':
        """从字典创建实例"""
        collection = cls()
        for result_data in data.get("variant_results", []):
            collection.add_variant(VariantResult.from_dict(result_data))
        for result_data in data.get("sensitivity_results", []):
            collection.add_sensitivity(SensitivityResult.from_dict(result_data))
        return collection
    
    def to_json(self, json_path: Path) -> None:
        """保存为JSON文件"""
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
    
    @classmethod
    def from_json(cls, json_path: Path) -> 'AblationResultCollection':
        """从JSON文件加载"""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    def get_summary(self) -> str:
        """获取结果集合摘要"""
        summary = f"消融实验结果集合:\n"
        summary += "=" * 60 + "\n"
        summary += f"\n变体结果 ({len(self.variant_results)} 项):\n"
        summary += "-" * 60 + "\n"
        for result in self.variant_results:
            summary += result.get_summary() + "\n"
        summary += f"\n敏感性结果 ({len(self.sensitivity_results)} 项):\n"
        summary += "-" * 60 + "\n"
        for result in self.sensitivity_results:
            summary += result.get_summary() + "\n"
        return summary
    
    def __str__(self) -> str:
        return self.get_summary()
