                      
                       
"""
实验数据模型模块
"""

from .benchmark_result import BenchmarkResult
from .simulation_result import (
    SimulationResult,
    LatencyMetrics,
    ResourceMetrics,
    CommunicationMetrics
)
from .detection_result import DetectionResult
from .ablation_result import VariantResult, SensitivityResult

__all__ = [
    "BenchmarkResult",
    "SimulationResult",
    "LatencyMetrics",
    "ResourceMetrics",
    "CommunicationMetrics",
    "DetectionResult",
    "VariantResult",
    "SensitivityResult",
]
