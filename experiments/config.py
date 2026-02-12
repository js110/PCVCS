#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实验配置管理模块
提供实验参数的配置和加载功能
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class ExperimentConfig:
    """实验配置类"""
    
    # 密码学参数
    ring_sizes: List[int] = field(default_factory=lambda: [4, 8, 16])
    merkle_leaf_counts: List[int] = field(default_factory=lambda: [10, 50, 100, 200])
    bulletproof_batch_sizes: List[int] = field(default_factory=lambda: [1, 10, 100])
    geohash_precisions: List[int] = field(default_factory=lambda: [5, 6, 7])
    
    # 仿真参数
    simulation_scenarios: List[Dict[str, Any]] = field(default_factory=lambda: [
        {"name": "light", "vehicles": 20, "duration": 3600},
        {"name": "medium", "vehicles": 50, "duration": 3600},
        {"name": "heavy", "vehicles": 100, "duration": 3600}
    ])
    
    # 安全测试参数
    attack_sample_count: int = 100
    attack_types: List[str] = field(default_factory=lambda: [
        "location_forge", "time_forge", "token_abuse", "replay", "duplicate"
    ])
    
    # 基准测试参数
    benchmark_iterations: int = 100
    
    # 输出配置
    output_dir: str = "./experiment_results"
    chart_format: str = "pdf"
    chart_dpi: int = 300
    language: str = "en"  # "en" or "zh"
    
    # 日志配置
    log_level: str = "INFO"
    log_file: str = "experiment.log"
    
    # 性能配置
    enable_parallel: bool = True
    max_workers: int = 4
    
    # SUMO配置
    sumo_home: str = "D:/sumo"  # SUMO安装路径
    
    @classmethod
    def from_json(cls, json_path: Path) -> 'ExperimentConfig':
        """从JSON文件加载配置"""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls(**data)
    
    def to_json(self, json_path: Path) -> None:
        """保存配置到JSON文件"""
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(asdict(self), f, indent=2, ensure_ascii=False)
    
    def validate(self) -> bool:
        """验证配置参数的有效性"""
        # 验证环大小
        if not all(size > 0 for size in self.ring_sizes):
            raise ValueError("Ring sizes must be positive")
        
        # 验证Merkle叶子数量
        if not all(count > 0 for count in self.merkle_leaf_counts):
            raise ValueError("Merkle leaf counts must be positive")
        
        # 验证Bulletproof批量大小
        if not all(size > 0 for size in self.bulletproof_batch_sizes):
            raise ValueError("Bulletproof batch sizes must be positive")
        
        # 验证仿真场景
        for scenario in self.simulation_scenarios:
            if "name" not in scenario or "vehicles" not in scenario or "duration" not in scenario:
                raise ValueError("Simulation scenario must have name, vehicles, and duration")
            if scenario["vehicles"] <= 0 or scenario["duration"] <= 0:
                raise ValueError("Vehicles and duration must be positive")
        
        # 验证攻击样本数量
        if self.attack_sample_count <= 0:
            raise ValueError("Attack sample count must be positive")
        
        # 验证基准测试迭代次数
        if self.benchmark_iterations <= 0:
            raise ValueError("Benchmark iterations must be positive")
        
        # 验证语言设置
        if self.language not in ["en", "zh"]:
            raise ValueError("Language must be 'en' or 'zh'")
        
        # 验证图表格式
        if self.chart_format not in ["pdf", "png", "svg"]:
            raise ValueError("Chart format must be 'pdf', 'png', or 'svg'")
        
        # 验证DPI
        if self.chart_dpi <= 0:
            raise ValueError("Chart DPI must be positive")
        
        return True
    
    def get_output_dir(self) -> Path:
        """获取输出目录路径"""
        return Path(self.output_dir)
    
    def get_log_file(self) -> Path:
        """获取日志文件路径"""
        return self.get_output_dir() / self.log_file


def load_config(config_path: Optional[Path] = None) -> ExperimentConfig:
    """
    加载实验配置
    
    Args:
        config_path: 配置文件路径，如果为None则使用默认配置
    
    Returns:
        ExperimentConfig实例
    """
    if config_path is None or not config_path.exists():
        # 使用默认配置
        config = ExperimentConfig()
    else:
        # 从文件加载配置
        config = ExperimentConfig.from_json(config_path)
    
    # 验证配置
    config.validate()
    
    return config


def create_default_config(output_path: Path) -> None:
    """
    创建默认配置文件
    
    Args:
        output_path: 输出文件路径
    """
    config = ExperimentConfig()
    config.to_json(output_path)
    print(f"Default configuration saved to: {output_path}")
