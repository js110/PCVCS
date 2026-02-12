#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
仿真结果数据模型
"""

import json
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class LatencyMetrics:
    """延迟指标"""
    avg_ms: float = 0.0  # 平均延迟（毫秒）
    p50_ms: float = 0.0  # 50%分位延迟
    p95_ms: float = 0.0  # 95%分位延迟
    p99_ms: float = 0.0  # 99%分位延迟
    max_ms: float = 0.0  # 最大延迟
    min_ms: float = 0.0  # 最小延迟
    
    @classmethod
    def from_measurements(cls, latencies_ms: List[float]) -> 'LatencyMetrics':
        """从测量数据创建延迟指标"""
        if not latencies_ms:
            return cls()
        
        latencies_array = np.array(latencies_ms)
        return cls(
            avg_ms=float(np.mean(latencies_array)),
            p50_ms=float(np.percentile(latencies_array, 50)),
            p95_ms=float(np.percentile(latencies_array, 95)),
            p99_ms=float(np.percentile(latencies_array, 99)),
            max_ms=float(np.max(latencies_array)),
            min_ms=float(np.min(latencies_array))
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LatencyMetrics':
        """从字典创建实例"""
        return cls(**data)


@dataclass
class ResourceMetrics:
    """资源占用指标"""
    avg_cpu_percent: float = 0.0  # 平均CPU使用率（%）
    max_cpu_percent: float = 0.0  # 最大CPU使用率（%）
    avg_memory_mb: float = 0.0  # 平均内存占用（MB）
    max_memory_mb: float = 0.0  # 最大内存占用（MB）
    
    @classmethod
    def from_measurements(cls, cpu_percents: List[float], memory_mbs: List[float]) -> 'ResourceMetrics':
        """从测量数据创建资源指标"""
        if not cpu_percents or not memory_mbs:
            return cls()
        
        cpu_array = np.array(cpu_percents)
        memory_array = np.array(memory_mbs)
        
        return cls(
            avg_cpu_percent=float(np.mean(cpu_array)),
            max_cpu_percent=float(np.max(cpu_array)),
            avg_memory_mb=float(np.mean(memory_array)),
            max_memory_mb=float(np.max(memory_array))
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ResourceMetrics':
        """从字典创建实例"""
        return cls(**data)


@dataclass
class CommunicationMetrics:
    """通信开销指标"""
    avg_packet_size_bytes: float = 0.0  # 平均数据包大小（字节）
    total_data_kb: float = 0.0  # 总数据量（KB）
    packet_count: int = 0  # 数据包数量
    
    @classmethod
    def from_measurements(cls, packet_sizes_bytes: List[int]) -> 'CommunicationMetrics':
        """从测量数据创建通信指标"""
        if not packet_sizes_bytes:
            return cls()
        
        sizes_array = np.array(packet_sizes_bytes)
        total_bytes = np.sum(sizes_array)
        
        return cls(
            avg_packet_size_bytes=float(np.mean(sizes_array)),
            total_data_kb=float(total_bytes / 1024),
            packet_count=len(packet_sizes_bytes)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CommunicationMetrics':
        """从字典创建实例"""
        return cls(**data)


@dataclass
class SimulationResult:
    """仿真结果数据结构"""
    scenario_name: str  # 场景名称
    vehicle_count: int  # 车辆数量
    total_packets: int  # 总数据包数
    latency_metrics: LatencyMetrics = field(default_factory=LatencyMetrics)
    throughput_qps: float = 0.0  # 吞吐量（QPS）
    resource_metrics: ResourceMetrics = field(default_factory=ResourceMetrics)
    communication_metrics: CommunicationMetrics = field(default_factory=CommunicationMetrics)
    use_zkp: bool = True  # 是否使用零知识证明
    duration_seconds: float = 0.0  # 仿真时长（秒）
    success_count: int = 0  # 成功验证数量
    failure_count: int = 0  # 失败验证数量
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        data = asdict(self)
        # 确保嵌套对象也被正确序列化
        data['latency_metrics'] = self.latency_metrics.to_dict()
        data['resource_metrics'] = self.resource_metrics.to_dict()
        data['communication_metrics'] = self.communication_metrics.to_dict()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SimulationResult':
        """从字典创建实例"""
        # 处理嵌套对象
        if 'latency_metrics' in data and isinstance(data['latency_metrics'], dict):
            data['latency_metrics'] = LatencyMetrics.from_dict(data['latency_metrics'])
        if 'resource_metrics' in data and isinstance(data['resource_metrics'], dict):
            data['resource_metrics'] = ResourceMetrics.from_dict(data['resource_metrics'])
        if 'communication_metrics' in data and isinstance(data['communication_metrics'], dict):
            data['communication_metrics'] = CommunicationMetrics.from_dict(data['communication_metrics'])
        return cls(**data)
    
    def to_json(self, json_path: Path) -> None:
        """保存为JSON文件"""
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
    
    @classmethod
    def from_json(cls, json_path: Path) -> 'SimulationResult':
        """从JSON文件加载"""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    def get_success_rate(self) -> float:
        """获取成功率"""
        if self.total_packets == 0:
            return 0.0
        return self.success_count / self.total_packets
    
    def get_summary(self) -> str:
        """获取结果摘要"""
        summary = f"仿真结果 - {self.scenario_name}:\n"
        summary += f"  车辆数量: {self.vehicle_count}\n"
        summary += f"  使用ZKP: {'是' if self.use_zkp else '否'}\n"
        summary += f"  总数据包: {self.total_packets}\n"
        summary += f"  成功/失败: {self.success_count}/{self.failure_count}\n"
        summary += f"  成功率: {self.get_success_rate()*100:.2f}%\n"
        # 注意：不再报告吞吐量，避免误导
        summary += f"  平均延迟: {self.latency_metrics.avg_ms:.4f} ms\n"
        summary += f"  95%分位延迟: {self.latency_metrics.p95_ms:.4f} ms\n"
        summary += f"  99%分位延迟: {self.latency_metrics.p99_ms:.4f} ms\n"
        summary += f"  平均消息大小: {self.communication_metrics.avg_packet_size_bytes:.0f} bytes\n"
        # 注意：CPU监控粒度太粗，不再报告
        summary += f"  平均内存: {self.resource_metrics.avg_memory_mb:.2f} MB\n"
        return summary
    
    def __str__(self) -> str:
        return self.get_summary()


class SimulationResultCollection:
    """仿真结果集合"""
    
    def __init__(self):
        self.results: List[SimulationResult] = []
    
    def add(self, result: SimulationResult) -> None:
        """添加结果"""
        self.results.append(result)
    
    def get_by_scenario(self, scenario_name: str) -> List[SimulationResult]:
        """根据场景名称获取结果"""
        return [r for r in self.results if r.scenario_name == scenario_name]
    
    def get_zkp_results(self) -> List[SimulationResult]:
        """获取使用ZKP的结果"""
        return [r for r in self.results if r.use_zkp]
    
    def get_naive_results(self) -> List[SimulationResult]:
        """获取朴素方案的结果"""
        return [r for r in self.results if not r.use_zkp]
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "results": [r.to_dict() for r in self.results],
            "count": len(self.results)
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SimulationResultCollection':
        """从字典创建实例"""
        collection = cls()
        for result_data in data.get("results", []):
            collection.add(SimulationResult.from_dict(result_data))
        return collection
    
    def to_json(self, json_path: Path) -> None:
        """保存为JSON文件"""
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
    
    @classmethod
    def from_json(cls, json_path: Path) -> 'SimulationResultCollection':
        """从JSON文件加载"""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    def get_summary(self) -> str:
        """获取结果集合摘要"""
        summary = f"仿真结果集合 ({len(self.results)} 项):\n"
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
