                      
                       

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class ExperimentConfig:
    
           
    ring_sizes: List[int] = field(default_factory=lambda: [4, 8, 16])
    merkle_leaf_counts: List[int] = field(default_factory=lambda: [10, 50, 100, 200])
    bulletproof_batch_sizes: List[int] = field(default_factory=lambda: [1, 10, 100])
    geohash_precisions: List[int] = field(default_factory=lambda: [5, 6, 7])
    
          
    simulation_scenarios: List[Dict[str, Any]] = field(default_factory=lambda: [
        {"name": "light", "vehicles": 20, "duration": 3600},
        {"name": "medium", "vehicles": 50, "duration": 3600},
        {"name": "heavy", "vehicles": 100, "duration": 3600}
    ])
    
            
    attack_sample_count: int = 100
    attack_types: List[str] = field(default_factory=lambda: [
        "location_forge", "time_forge", "token_abuse", "replay", "duplicate"
    ])
    
            
    benchmark_iterations: int = 100
    
          
    output_dir: str = "./experiment_results"
    chart_format: str = "pdf"
    chart_dpi: int = 300
    language: str = "en"                
    
          
    log_level: str = "INFO"
    log_file: str = "experiment.log"
    
          
    enable_parallel: bool = True
    max_workers: int = 4
    
            
    sumo_home: str = "D:/sumo"            
    
    @classmethod
    def from_json(cls, json_path: Path) -> 'ExperimentConfig':
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls(**data)
    
    def to_json(self, json_path: Path) -> None:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(asdict(self), f, indent=2, ensure_ascii=False)
    
    def validate(self) -> bool:
               
        if not all(size > 0 for size in self.ring_sizes):
            raise ValueError("Ring sizes must be positive")
        
                      
        if not all(count > 0 for count in self.merkle_leaf_counts):
            raise ValueError("Merkle leaf counts must be positive")
        
                           
        if not all(size > 0 for size in self.bulletproof_batch_sizes):
            raise ValueError("Bulletproof batch sizes must be positive")
        
                
        for scenario in self.simulation_scenarios:
            if "name" not in scenario or "vehicles" not in scenario or "duration" not in scenario:
                raise ValueError("Simulation scenario must have name, vehicles, and duration")
            if scenario["vehicles"] <= 0 or scenario["duration"] <= 0:
                raise ValueError("Vehicles and duration must be positive")
        
                  
        if self.attack_sample_count <= 0:
            raise ValueError("Attack sample count must be positive")
        
                    
        if self.benchmark_iterations <= 0:
            raise ValueError("Benchmark iterations must be positive")
        
                
        if self.language not in ["en", "zh"]:
            raise ValueError("Language must be 'en' or 'zh'")
        
                
        if self.chart_format not in ["pdf", "png", "svg"]:
            raise ValueError("Chart format must be 'pdf', 'png', or 'svg'")
        
               
        if self.chart_dpi <= 0:
            raise ValueError("Chart DPI must be positive")
        
        return True
    
    def get_output_dir(self) -> Path:
        return Path(self.output_dir)
    
    def get_log_file(self) -> Path:
        return self.get_output_dir() / self.log_file


def load_config(config_path: Optional[Path] = None) -> ExperimentConfig:
    if config_path is None or not config_path.exists():
                
        config = ExperimentConfig()
    else:
                 
        config = ExperimentConfig.from_json(config_path)
    
          
    config.validate()
    
    return config


def create_default_config(output_path: Path) -> None:
    config = ExperimentConfig()
    config.to_json(output_path)
    print(f"Default configuration saved to: {output_path}")
