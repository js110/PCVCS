#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基准测试结果数据模型
"""

import json
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class BenchmarkResult:
    """基准测试结果数据结构"""
    
    operation: str  # 操作名称（如"Ed25519签名"）
    avg_time_ms: float  # 平均时间（毫秒）
    std_time_ms: float = 0.0  # 标准差（毫秒）
    min_time_ms: float = 0.0  # 最小时间（毫秒）
    max_time_ms: float = 0.0  # 最大时间（毫秒）
    size_bytes: int = 0  # 大小（字节）
    iterations: int = 1  # 迭代次数
    parameters: Dict[str, Any] = field(default_factory=dict)  # 额外参数
    
    @classmethod
    def from_measurements(cls, operation: str, times_ms: List[float],
                         size_bytes: int = 0, parameters: Optional[Dict[str, Any]] = None) -> 'BenchmarkResult':
        """
        从测量数据创建结果对象
        
        Args:
            operation: 操作名称
            times_ms: 时间测量列表（毫秒）
            size_bytes: 大小（字节）
            parameters: 额外参数
        
        Returns:
            BenchmarkResult实例
        """
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
        """转换为字典"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BenchmarkResult':
        """从字典创建实例"""
        return cls(**data)
    
    def to_json(self, json_path: Path) -> None:
        """保存为JSON文件"""
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
    
    @classmethod
    def from_json(cls, json_path: Path) -> 'BenchmarkResult':
        """从JSON文件加载"""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    def get_summary(self) -> str:
        """获取结果摘要"""
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
    """基准测试结果集合"""
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
    
    def add(self, result: BenchmarkResult) -> None:
        """添加结果"""
        self.results.append(result)
    
    def get_by_operation(self, operation: str) -> Optional[BenchmarkResult]:
        """根据操作名称获取结果"""
        for result in self.results:
            if result.operation == operation:
                return result
        return None
    
    def get_by_parameter(self, param_name: str, param_value: Any) -> List[BenchmarkResult]:
        """根据参数筛选结果"""
        return [r for r in self.results 
                if param_name in r.parameters and r.parameters[param_name] == param_value]
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "results": [r.to_dict() for r in self.results],
            "count": len(self.results)
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BenchmarkResultCollection':
        """从字典创建实例"""
        collection = cls()
        for result_data in data.get("results", []):
            collection.add(BenchmarkResult.from_dict(result_data))
        return collection
    
    def to_json(self, json_path: Path) -> None:
        """保存为JSON文件"""
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
    
    @classmethod
    def from_json(cls, json_path: Path) -> 'BenchmarkResultCollection':
        """从JSON文件加载"""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    def get_summary(self) -> str:
        """获取结果集合摘要"""
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
