                      
                       

import os
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List

from .config import ExperimentConfig
from .logger import ExperimentLogger, setup_logger
from .modules.crypto_benchmark import CryptoBenchmark
from .modules.end_to_end_simulator import EndToEndSimulator
from .modules.security_tester import SecurityTester
from .modules.ablation_experiment import AblationExperiment


class ExperimentController:
    
    def __init__(self, config: ExperimentConfig):
        self.config = config
        
                
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.output_dir = Path(config.output_dir) / timestamp
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
               
        (self.output_dir / "raw_data").mkdir(exist_ok=True)
        (self.output_dir / "charts").mkdir(exist_ok=True)
        (self.output_dir / "reports").mkdir(exist_ok=True)
        
              
        log_file = self.output_dir / "reports" / config.log_file
        self.logger = setup_logger("experiment", log_file, config.log_level)
        
              
        config.to_json(self.output_dir / "config.json")
        
        self.logger.info(f"实验输出目录: {self.output_dir}")
    
    def verify_environment(self) -> bool:
        self.logger.section("验证实验环境")
        
        try:
                        
            import sys
            python_version = sys.version_info
            self.logger.info(f"Python版本: {python_version.major}.{python_version.minor}.{python_version.micro}")
            
            if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 8):
                self.logger.error("需要Python 3.8或更高版本")
                return False
            
                    
            required_libs = ["numpy", "matplotlib", "psutil"]
            for lib in required_libs:
                try:
                    __import__(lib)
                    self.logger.info(f"✓ {lib} 已安装")
                except ImportError:
                    self.logger.error(f"✗ {lib} 未安装")
                    return False
            
                    
            try:
                import nacl
                self.logger.info("✓ PyNaCl 已安装")
            except ImportError:
                self.logger.warning("⚠ PyNaCl 未安装，将使用占位符实现")
            
            self.logger.info("环境验证通过")
            return True
            
        except Exception as e:
            self.logger.exception(f"环境验证失败: {e}")
            return False
    
    def run_crypto_benchmark(self) -> bool:
        self.logger.section("运行密码学基准测试")
        
        try:
            benchmark = CryptoBenchmark(self.logger)
            results = benchmark.run_all({
                "benchmark_iterations": self.config.benchmark_iterations,
                "ring_sizes": self.config.ring_sizes,
                "merkle_leaf_counts": self.config.merkle_leaf_counts,
                "bulletproof_batch_sizes": self.config.bulletproof_batch_sizes
            })
            
            output_path = self.output_dir / "raw_data" / "crypto_benchmarks.json"
            benchmark.save_results(output_path)
            
            self.logger.info("密码学基准测试完成")
            return True
            
        except Exception as e:
            self.logger.exception(f"密码学基准测试失败: {e}")
            return False
    
    def run_end_to_end_simulation(self) -> bool:
        self.logger.section("运行端到端仿真")
        
        try:
            simulator = EndToEndSimulator(self.logger, sumo_home=self.config.sumo_home)
            results = simulator.run_all_scenarios(self.config.simulation_scenarios)
            
            output_path = self.output_dir / "raw_data" / "end_to_end_simulations.json"
            simulator.save_results(output_path)
            
            self.logger.info("端到端仿真完成")
            return True
            
        except Exception as e:
            self.logger.exception(f"端到端仿真失败: {e}")
            return False
    
    def run_security_tests(self) -> bool:
        self.logger.section("运行安全性测试")
        
        try:
            tester = SecurityTester(self.logger)
            results = tester.run_all_tests(
                self.config.attack_types,
                self.config.attack_sample_count
            )
            
            output_path = self.output_dir / "raw_data" / "security_tests.json"
            tester.save_results(output_path)
            
            self.logger.info("安全性测试完成")
            return True
            
        except Exception as e:
            self.logger.exception(f"安全性测试失败: {e}")
            return False
    
    def run_ablation_experiments(self) -> bool:
        self.logger.section("运行消融实验")
        
        try:
            experiment = AblationExperiment(self.logger)
            results = experiment.run_all_experiments()
            
            output_path = self.output_dir / "raw_data" / "ablation_experiments.json"
            experiment.save_results(output_path)
            
            self.logger.info("消融实验完成")
            return True
            
        except Exception as e:
            self.logger.exception(f"消融实验失败: {e}")
            return False
    
    def generate_summary(self, results: dict) -> None:
        self.logger.section("生成实验摘要")
        
        summary = {
            "timestamp": datetime.now().isoformat(),
            "config": self.config.__dict__,
            "results": results,
            "output_dir": str(self.output_dir)
        }
        
        summary_path = self.output_dir / "reports" / "summary.json"
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"实验摘要已保存到: {summary_path}")
    
    def run_all(self, modules: Optional[List[str]] = None) -> dict:
        self.logger.section("开始综合实验")
        self.logger.info(f"配置: {self.config}")
        
              
        if not self.verify_environment():
            self.logger.error("环境验证失败，终止实验")
            return {"success": False, "error": "environment_verification_failed"}
        
        results = {
            "success": True,
            "modules": {}
        }
        
                  
        all_modules = ["crypto_benchmark", "end_to_end", "security", "ablation"]
        if modules is None:
            modules = all_modules
        
                
        if "crypto_benchmark" in modules:
            results["modules"]["crypto_benchmark"] = self.run_crypto_benchmark()
        
        if "end_to_end" in modules:
            results["modules"]["end_to_end"] = self.run_end_to_end_simulation()
        
        if "security" in modules:
            results["modules"]["security"] = self.run_security_tests()
        
        if "ablation" in modules:
            results["modules"]["ablation"] = self.run_ablation_experiments()
        
              
        self.generate_summary(results)
        
              
        self.logger.section("实验完成")
        for module, success in results["modules"].items():
            status = "✓ 成功" if success else "✗ 失败"
            self.logger.info(f"{module}: {status}")
        
        self.logger.info(f"所有结果已保存到: {self.output_dir}")
        
        return results
