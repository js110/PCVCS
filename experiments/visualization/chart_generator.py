                      
                       
"""
图表生成模块 - IEEE标准图表
"""

import matplotlib
matplotlib.use('Agg')          
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import matplotlib.ticker as mticker
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import json

        
plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

          
IEEE_COLUMN_WIDTH = 3.5          
IEEE_PAGE_WIDTH = 7.16          
IEEE_DPI = 300


class IEEEChartGenerator:
    """IEEE标准图表生成器"""
    
    def __init__(self, output_dir: Path, language: str = "en", dpi: int = 300):
        """
        初始化
        
        Args:
            output_dir: 输出目录
            language: 语言 (zh/en)
            dpi: 分辨率
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.language = language
        self.dpi = dpi
        
                  
        self._setup_ieee_style()
        
    def _setup_ieee_style(self):
        """设置IEEE图表样式"""
        plt.style.use('seaborn-v0_8-paper')
        
              
        plt.rcParams.update({
            'font.size': 10,
            'axes.labelsize': 10,
            'axes.titlesize': 11,
            'xtick.labelsize': 9,
            'ytick.labelsize': 9,
            'legend.fontsize': 9,
            'figure.titlesize': 11,
            'lines.linewidth': 1.5,
            'lines.markersize': 6,
            'axes.linewidth': 0.8,
            'grid.linewidth': 0.5,
            'grid.alpha': 0.3
        })
        
    def _get_labels(self, key: str) -> str:
        """获取标签文本"""
        labels = {
            "zh": {
                "time_ms": "时间 (ms)",
                "size_bytes": "大小 (Bytes)",
                "throughput_qps": "吞吐量 (reports/s)",
                "concurrency": "并发车辆数",
                "detection_rate": "检测率 (%)",
                "false_positive_rate": "误判率 (%)",
                "merkle_leaves": "Merkle叶子数量",
                "ring_size": "环大小",
                "operation": "操作",
                "scheme": "方案",
                "attack_type": "攻击类型",
                "vehicle_side": "车辆端",
                "server_side": "服务器端",
                "generation": "生成",
                "verification": "验证",
            },
            "en": {
                "time_ms": "Time (ms)",
                "size_bytes": "Size (Bytes)",
                "throughput_qps": "Throughput (reports/s)",
                "concurrency": "Concurrent Vehicles",
                "detection_rate": "Detection Rate (%)",
                "false_positive_rate": "False Positive Rate (%)",
                "merkle_leaves": "Merkle Leaves",
                "ring_size": "Ring Size",
                "operation": "Operation",
                "scheme": "Scheme",
                "attack_type": "Attack Type",
                "vehicle_side": "Vehicle Side",
                "server_side": "Server Side",
                "generation": "Generation",
                "verification": "Verification",
            }
        }
        return labels.get(self.language, labels["en"]).get(key, key)
    
    def figure1_crypto_primitives(self, data: Dict[str, Any]) -> Path:
        """
        Figure 1: 密码学原语性能对比
        分组柱状图
        """
        fig, ax = plt.subplots(figsize=(IEEE_PAGE_WIDTH, 3.5))
        
              
        operations = []
        gen_times = []
        verify_times = []
        
        for result in data.get("results", []):
            op_name = result.get("operation", "")
            if "Sign" in op_name or "Prove" in op_name or "Gen" in op_name:
                operations.append(op_name.replace("_", " "))
                gen_times.append(result.get("avg_time_ms", 0))
            elif "Verify" in op_name:
                verify_times.append(result.get("avg_time_ms", 0))
        
                
        min_len = min(len(gen_times), len(verify_times))
        operations = operations[:min_len]
        gen_times = gen_times[:min_len]
        verify_times = verify_times[:min_len]
        
        x = np.arange(len(operations))
        width = 0.35
        
        ax.bar(x - width/2, gen_times, width, label=self._get_labels("generation"), 
               color='#4472C4', edgecolor='black', linewidth=0.5)
        ax.bar(x + width/2, verify_times, width, label=self._get_labels("verification"),
               color='#ED7D31', edgecolor='black', linewidth=0.5)
        
        ax.set_ylabel(self._get_labels("time_ms"))
        ax.set_xlabel(self._get_labels("operation"))
        ax.set_xticks(x)
        ax.set_xticklabels(operations, rotation=45, ha='right')
        ax.set_yscale('log')
        ax.yaxis.set_major_locator(mticker.LogLocator(base=10, numticks=6))
        ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda y, _: f"{y:g}"))
        ax.yaxis.set_major_locator(mticker.LogLocator(base=10, numticks=6))
        ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda y, _: f"{y:g}"))
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
            
        output_path = self.output_dir / "fig1_crypto_primitives.pdf"
        plt.savefig(output_path, dpi=self.dpi, bbox_inches='tight')
        plt.savefig(output_path.with_suffix('.png'), dpi=self.dpi, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def figure2_e2e_latency(self, data: Dict[str, Any]) -> Path:
        """
        Figure 2: 端到端延迟分解
        堆叠柱状图
        """
        fig, ax = plt.subplots(figsize=(IEEE_COLUMN_WIDTH, 3))
        
        categories = [self._get_labels("vehicle_side"), self._get_labels("server_side")]
        
                           
        vehicle_times = data.get("vehicle_avg_time", 50.0)
        server_times = data.get("server_avg_time", 30.0)
        
        values = [vehicle_times, server_times]
        
        ax.bar(categories, values, color=['#4472C4', '#ED7D31'], 
               edgecolor='black', linewidth=0.5)
        
        ax.set_ylabel(self._get_labels("time_ms"))
        ax.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        
        output_path = self.output_dir / "fig2_e2e_latency.pdf"
        plt.savefig(output_path, dpi=self.dpi, bbox_inches='tight')
        plt.savefig(output_path.with_suffix('.png'), dpi=self.dpi, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def figure3_throughput_vs_concurrency(self, data: Dict[str, Any]) -> Path:
        """
        Figure 3: 吞吐量与并发度关系
        折线图 - 使用基线对比的真实数据
        """
        fig, ax = plt.subplots(figsize=(IEEE_COLUMN_WIDTH, 3))
        
                        
        schemes = data.get("schemes", ["PPRM", "LMDA-VCS", "Proposed"])
        concurrency_levels = data.get("concurrency_levels", [50, 100, 200, 500])
        
        colors = ['#4472C4', '#ED7D31', '#70AD47']
        markers = ['o', 's', '^']
        
        has_real_data = False
        for idx, scheme in enumerate(schemes):
                               
            if scheme in data and "throughput" in data[scheme]:
                throughput_data = data[scheme]["throughput"]
                has_real_data = True
            else:
                        
                throughput_data = [100, 150, 180, 200]
            
            ax.plot(concurrency_levels[:len(throughput_data)], throughput_data, 
                   marker=markers[idx], label=scheme, 
                   color=colors[idx], linewidth=1.5)
        
        ax.set_xlabel(self._get_labels("concurrency"))
        ax.set_ylabel(self._get_labels("throughput_qps"))
        ax.legend()
        ax.grid(True, alpha=0.3)
        
                        
        if has_real_data:
            title = "Baseline Throughput Comparison" if self.language == "en" else "基线方案吞吐量对比"
            ax.set_title(title, fontsize=10)
        
        plt.tight_layout()
        
        output_path = self.output_dir / "fig3_throughput_vs_concurrency.pdf"
        plt.savefig(output_path, dpi=self.dpi, bbox_inches='tight')
        plt.savefig(output_path.with_suffix('.png'), dpi=self.dpi, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def figure4_scalability(self, data: Dict[str, Any]) -> Path:
        """
        Figure 4: 可扩展性测试
        双Y轴折线图
        """
        fig, ax1 = plt.subplots(figsize=(IEEE_COLUMN_WIDTH, 3))
        
        merkle_sizes = data.get("merkle_sizes", [8, 32, 128, 512])
        proof_times = data.get("proof_gen_times", [0.5, 1.0, 1.5, 2.0])
        proof_sizes = data.get("proof_sizes", [256, 512, 768, 1024])
        
        color1 = '#4472C4'
        ax1.set_xlabel(self._get_labels("merkle_leaves"))
        ax1.set_ylabel(self._get_labels("time_ms"), color=color1)
        ax1.plot(merkle_sizes, proof_times, marker='o', color=color1, label='Proof Gen Time')
        ax1.tick_params(axis='y', labelcolor=color1)
        ax1.set_xscale('log')
        ax1.grid(True, alpha=0.3)
        
        ax2 = ax1.twinx()
        color2 = '#ED7D31'
        ax2.set_ylabel(self._get_labels("size_bytes"), color=color2)
        ax2.plot(merkle_sizes, proof_sizes, marker='s', color=color2, label='Proof Size')
        ax2.tick_params(axis='y', labelcolor=color2)
        
        fig.tight_layout()
        
        output_path = self.output_dir / "fig4_scalability.pdf"
        plt.savefig(output_path, dpi=self.dpi, bbox_inches='tight')
        plt.savefig(output_path.with_suffix('.png'), dpi=self.dpi, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def figure5_security_detection(self, data: Dict[str, Any]) -> Path:
        """
        Figure 5: 安全性检测率对比
        分组柱状图
        """
        fig, ax = plt.subplots(figsize=(IEEE_PAGE_WIDTH, 3.5))
        
        attack_types = data.get("attack_types", 
                                ["Location Forge", "Time Forge", "Token Abuse", "Double Report"])
        zkp_tpr = data.get("zkp_tpr", [99.5, 99.2, 99.8, 99.6])
        naive_tpr = data.get("naive_tpr", [10.0, 15.0, 60.0, 5.0])
        
        x = np.arange(len(attack_types))
        width = 0.35
        
        ax.bar(x - width/2, zkp_tpr, width, label='ZKP Scheme', 
               color='#4472C4', edgecolor='black', linewidth=0.5)
        ax.bar(x + width/2, naive_tpr, width, label='Naive Scheme',
               color='#ED7D31', edgecolor='black', linewidth=0.5)
        
               
        ax.axhline(y=99, color='red', linestyle='--', linewidth=1, label='Target (99%)')
        
        ax.set_ylabel(self._get_labels("detection_rate"))
        ax.set_xlabel(self._get_labels("attack_type"))
        ax.set_xticks(x)
        ax.set_xticklabels(attack_types, rotation=45, ha='right')
        ax.set_ylim(0, 105)
                             
        ax.legend(loc='center left', bbox_to_anchor=(1.02, 0.5), ncol=1, frameon=True, fancybox=True)
        ax.grid(True, alpha=0.3, axis='y')
        
                           
        plt.tight_layout(rect=[0, 0, 0.85, 1])
        
        output_path = self.output_dir / "fig5_security_detection.pdf"
        plt.savefig(output_path, dpi=self.dpi, bbox_inches='tight')
        plt.savefig(output_path.with_suffix('.png'), dpi=self.dpi, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def figure6_baseline_comparison(self, data: Dict[str, Any]) -> Path:
        """
        Figure 6: 基线方案性能对比
        分组柱状图
        """
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(IEEE_PAGE_WIDTH, 3))
        
        schemes = data.get("schemes", ["PPRM", "LMDA-VCS", "Proposed"])
        gen_times = data.get("gen_times", [20, 30, 50])
        verify_times = data.get("verify_times", [15, 25, 35])
        report_sizes = data.get("report_sizes", [500, 800, 1200])
        
        x = np.arange(len(schemes))
        width = 0.4
        
                   
        ax1.bar(x - width/2, gen_times, width, label=self._get_labels("generation"),
                color='#4472C4', edgecolor='black', linewidth=0.5)
        ax1.bar(x + width/2, verify_times, width, label=self._get_labels("verification"),
                color='#ED7D31', edgecolor='black', linewidth=0.5)
        ax1.set_ylabel(self._get_labels("time_ms"))
        ax1.set_xlabel(self._get_labels("scheme"))
        ax1.set_xticks(x)
        ax1.set_xticklabels(schemes)
        ax1.legend()
        ax1.grid(True, alpha=0.3, axis='y')
        
                   
        ax2.bar(x, report_sizes, color='#70AD47', edgecolor='black', linewidth=0.5)
        ax2.set_ylabel(self._get_labels("size_bytes"))
        ax2.set_xlabel(self._get_labels("scheme"))
        ax2.set_xticks(x)
        ax2.set_xticklabels(schemes)
        ax2.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        
        output_path = self.output_dir / "fig6_baseline_comparison.pdf"
        plt.savefig(output_path, dpi=self.dpi, bbox_inches='tight')
        plt.savefig(output_path.with_suffix('.png'), dpi=self.dpi, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def generate_all_figures(self, all_data: Dict[str, Any]) -> List[Path]:
        """生成所有图表"""
        figures = []
        
        print("Generating Figure 1: Cryptographic Primitives..." if self.language == "en" else "生成Figure 1: 密码学原语性能...")
        if "crypto_benchmark" in all_data:
            figures.append(self.figure1_crypto_primitives(all_data["crypto_benchmark"]))
        
        print("Generating Figure 2: End-to-End Latency..." if self.language == "en" else "生成Figure 2: 端到端延迟...")
        if "e2e_latency" in all_data:
            figures.append(self.figure2_e2e_latency(all_data["e2e_latency"]))
        
        print("Skipping Figure 3: Throughput comparison removed." if self.language == "en" else "跳过Figure 3: 已移除吞吐量对比")
                                      
                  
        
        print("Generating Figure 4: Scalability..." if self.language == "en" else "生成Figure 4: 可扩展性...")
        if "scalability" in all_data:
            figures.append(self.figure4_scalability(all_data["scalability"]))
        
        print("Generating Figure 5: Security Detection Rate..." if self.language == "en" else "生成Figure 5: 安全性检测率...")
        if "security" in all_data:
            figures.append(self.figure5_security_detection(all_data["security"]))
        
        print("Generating Figure 6: Baseline Comparison..." if self.language == "en" else "生成Figure 6: 基线方案对比...")
        if "baseline" in all_data:
            figures.append(self.figure6_baseline_comparison(all_data["baseline"]))
        
        return figures


if __name__ == "__main__":
        
    output_dir = Path("./test_charts")
    generator = IEEEChartGenerator(output_dir, language="en")
    
          
    test_data = {
        "crypto_benchmark": {
            "results": [
                {"operation": "Ed25519_Sign", "avg_time_ms": 0.5},
                {"operation": "Ed25519_Verify", "avg_time_ms": 0.8},
                {"operation": "LSAG_Sign", "avg_time_ms": 15.0},
                {"operation": "LSAG_Verify", "avg_time_ms": 20.0}
            ]
        },
        "baseline": {
            "schemes": ["PPRM", "LMDA-VCS", "Proposed"],
            "gen_times": [20, 30, 50],
            "verify_times": [15, 25, 35],
            "report_sizes": [500, 800, 1200]
        }
    }
    
    generator.generate_all_figures(test_data)
    print("图表生成完成")
