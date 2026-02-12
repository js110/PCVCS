                      
                       
"""
生成中文版性能评估图表
用于论文第六部分 (VI. PERFORMANCE EVALUATION)
"""

import json
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

        
plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False
plt.rcParams.update({
    'font.size': 10,
    'axes.labelsize': 11,
    'axes.titlesize': 12,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'legend.fontsize': 9,
})


def load_data(data_dir: Path):
    """加载实验数据"""
    data = {}
    for exp_file in data_dir.glob("experiment*.json"):
        with open(exp_file, 'r', encoding='utf-8') as f:
            exp_name = exp_file.stem
            data[exp_name] = json.load(f)
    return data


def generate_fig1_client_breakdown(data, output_dir):
    """图1: 车辆端性能分解 (分组柱状图)"""
    fig, ax = plt.subplots(figsize=(12, 6))
    
    exp1 = data['experiment1_micro_benchmark']
    ring_sizes = exp1["ring_sizes"]
    breakdown = exp1["client_breakdown"]
    
    setup = [item["commitments_setup"] for item in breakdown]
    zk = [item["spatio_temporal_zk"] for item in breakdown]
    lsag = [item["lsag_signing"] for item in breakdown]
    kem = [item["ml_kem_encryption"] for item in breakdown]
    
             
    x = np.arange(len(ring_sizes))
    width = 0.2           
    
            
    bars1 = ax.bar(x - 1.5*width, setup, width, label='承诺与初始化', 
                   color='#FFC000', edgecolor='black', linewidth=1)
    bars2 = ax.bar(x - 0.5*width, zk, width, label='时空零知识证明', 
                   color='#4472C4', edgecolor='black', linewidth=1)
    bars3 = ax.bar(x + 0.5*width, lsag, width, label='LSAG环签名', 
                   color='#ED7D31', edgecolor='black', linewidth=1)
    bars4 = ax.bar(x + 1.5*width, kem, width, label='ML-KEM加密', 
                   color='#70AD47', edgecolor='black', linewidth=1)
    
                          
    for i, (s, z, l, k) in enumerate(zip(setup, zk, lsag, kem)):
        if s > 0.5:                     
            ax.text(i - 1.5*width, s + 0.2, f'{s:.1f}', ha='center', va='bottom', fontsize=7)
        ax.text(i - 0.5*width, z + 0.2, f'{z:.1f}', ha='center', va='bottom', fontsize=7)
        ax.text(i + 0.5*width, l + 0.2, f'{l:.1f}', ha='center', va='bottom', fontsize=7)
        ax.text(i + 1.5*width, k + 0.2, f'{k:.1f}', ha='center', va='bottom', fontsize=7)
    
                
    totals = [sum([s, z, l, k]) for s, z, l, k in zip(setup, zk, lsag, kem)]
    for i, total in enumerate(totals):
        ax.text(i, max([setup[i], zk[i], lsag[i], kem[i]]) + 1.0, 
                f'总计: {total:.1f} ms', ha='center', va='bottom', 
                fontsize=9, fontweight='bold', color='darkred')
    
    ax.set_xlabel('环大小 $n_R$', fontsize=11)
    ax.set_ylabel('时间 (ms)', fontsize=11)
    ax.set_title('车辆端计算时间分解（分组对比）', fontsize=12, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(ring_sizes)
    ax.legend(loc='center left', bbox_to_anchor=(1, 0.5), framealpha=0.95, 
              fontsize=10, edgecolor='black', fancybox=True)
    ax.grid(True, alpha=0.3, axis='y', linestyle='--')
    ax.set_ylim(0, max(max(zk), max(lsag), max(kem)) * 1.25)
    
    plt.tight_layout()
    plt.savefig(output_dir / "图1_车辆端性能分解.pdf", dpi=300, bbox_inches='tight')
    plt.savefig(output_dir / "图1_车辆端性能分解.png", dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ 图1: 车辆端性能分解")


def generate_fig2_server_breakdown(data, output_dir):
    """图2: 服务器端性能分解 (分组柱状图)"""
    fig, ax = plt.subplots(figsize=(11, 6))
    
    exp1 = data['experiment1_micro_benchmark']
    ring_sizes = exp1["ring_sizes"]
    breakdown = exp1["server_breakdown"]
    
    zk_ver = [item["zk_verification"] for item in breakdown]
    lrs_ver = [item["lrs_verification"] for item in breakdown]
    kem_dec = [item["kem_decapsulation"] for item in breakdown]
    
             
    x = np.arange(len(ring_sizes))
    width = 0.25           
    
            
    bars1 = ax.bar(x - width, zk_ver, width, label='零知识证明验证', 
                   color='#4472C4', edgecolor='black', linewidth=1)
    bars2 = ax.bar(x, lrs_ver, width, label='环签名验证', 
                   color='#ED7D31', edgecolor='black', linewidth=1)
    bars3 = ax.bar(x + width, kem_dec, width, label='KEM解封装', 
                   color='#70AD47', edgecolor='black', linewidth=1)
    
                 
    for i, (z, l, k) in enumerate(zip(zk_ver, lrs_ver, kem_dec)):
        ax.text(i - width, z + 0.15, f'{z:.1f}', ha='center', va='bottom', fontsize=8)
        ax.text(i, l + 0.15, f'{l:.1f}', ha='center', va='bottom', fontsize=8)
        ax.text(i + width, k + 0.15, f'{k:.1f}', ha='center', va='bottom', fontsize=8)
    
                
    totals = [sum([z, l, k]) for z, l, k in zip(zk_ver, lrs_ver, kem_dec)]
    for i, total in enumerate(totals):
        ax.text(i, max([zk_ver[i], lrs_ver[i], kem_dec[i]]) + 0.7, 
                f'总计: {total:.1f} ms', ha='center', va='bottom', 
                fontsize=9, fontweight='bold', color='darkred')
    
    ax.set_xlabel('环大小 $n_R$', fontsize=11)
    ax.set_ylabel('时间 (ms)', fontsize=11)
    ax.set_title('服务器端计算时间分解（分组对比）', fontsize=12, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(ring_sizes)
    ax.legend(loc='center left', bbox_to_anchor=(1, 0.5), framealpha=0.95, 
              fontsize=10, edgecolor='black', fancybox=True)
    ax.grid(True, alpha=0.3, axis='y', linestyle='--')
    ax.set_ylim(0, max(max(zk_ver), max(lrs_ver), max(kem_dec)) * 1.25)
    
    plt.tight_layout()
    plt.savefig(output_dir / "图2_服务器端性能分解.pdf", dpi=300, bbox_inches='tight')
    plt.savefig(output_dir / "图2_服务器端性能分解.png", dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ 图2: 服务器端性能分解")


def generate_fig3_communication(data, output_dir):
    """图3: 通信开销分析 (对比折线图)"""
    fig, ax = plt.subplots(figsize=(9, 6))
    
    exp2 = data['experiment2_communication']
    heights = exp2["merkle_heights"]
    sizes_kb = [item["size_kb"] for item in exp2["report_sizes"]]
    
                                       
    num_cells = [2**h for h in heights[:3]]                                           
    sizes_kb = sizes_kb[:3]             
    
                                
    ax.plot(num_cells, sizes_kb, marker='o', linewidth=2.5, markersize=10, 
            color='#4472C4', markerfacecolor='white', markeredgewidth=2.5, 
            label='PCVCS (Merkle树)', zorder=3)
    
                                               
    c0 = 6.0                           
    naive_sizes_kb = [c0 + (8 * n / 1024) for n in num_cells]                  
    
    ax.plot(num_cells, naive_sizes_kb, marker='s', linewidth=2.5, markersize=9,
            color='#FF6B35', linestyle='--', markerfacecolor='white', 
            markeredgewidth=2.5, markeredgecolor='#FF6B35', 
            label='Naive (列表编码)', alpha=0.9, zorder=2)
    
             
    ax.set_xscale('log', base=2)
    
                 
    ax.set_xticks(num_cells)
    ax.set_xticklabels([f'{n:,}' for n in num_cells], fontsize=10)
    
    ax.set_xlabel('授权区域数 $|A_\\tau|$', fontsize=12, fontweight='bold')
    ax.set_ylabel('报告大小 (KB)', fontsize=12, fontweight='bold')
    ax.set_title('报告大小与授权区域数的关系', fontsize=13, fontweight='bold')
    
        
    ax.legend(loc='upper left', framealpha=0.95, fontsize=11, 
              edgecolor='black', fancybox=True)
    
    ax.grid(True, alpha=0.3, linestyle='--', which='both')
    ax.set_ylim(0, max(max(sizes_kb), max(naive_sizes_kb)) * 1.15)
    
                  
    for n, s in zip(num_cells, sizes_kb):
        ax.text(n, s + max(naive_sizes_kb)*0.015, f'{s:.2f}', ha='center', va='bottom', 
                fontsize=10, color='#4472C4', fontweight='bold')
    
                   
    for i, (n, s) in enumerate(zip(num_cells, naive_sizes_kb)):
                    
        if i == 0:
            ax.text(n, s + max(naive_sizes_kb)*0.025, f'{s:.1f}', ha='center', va='bottom', 
                    fontsize=11, color='#FF6B35', fontweight='bold')
        elif i == len(num_cells) - 1:
            ax.text(n, s + max(naive_sizes_kb)*0.015, f'{s:.1f}', ha='center', va='bottom', 
                    fontsize=11, color='#FF6B35', fontweight='bold')
        else:
            ax.text(n, s + max(naive_sizes_kb)*0.02, f'{s:.1f}', ha='center', va='bottom', 
                    fontsize=10, color='#FF6B35', fontweight='bold')
    
          
    ax.text(0.98, 0.05, 
            '* PCVCS: O(log n) 增长 (Merkle证明)\n'
            '* Naive: O(n) 增长 (列表存储)', 
            transform=ax.transAxes, fontsize=10, 
            verticalalignment='bottom', horizontalalignment='right',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.3))
    
    plt.tight_layout()
    plt.savefig(output_dir / "图3_通信开销分析.pdf", dpi=300, bbox_inches='tight')
    plt.savefig(output_dir / "图3_通信开销分析.png", dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ 图3: 通信开销分析")


def generate_fig4_security(data, output_dir):
    """图4: 安全性验证 (2x1面板图)"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
    
    exp3 = data['experiment3_security']
    
                    
    categories = list(exp3["acceptance_rates"].keys())
    rates = list(exp3["acceptance_rates"].values())
    
            
    category_names = {
        "Honest": "诚实报告",
        "Fake Loc.": "伪造位置",
        "Fake Time": "伪造时间",
        "Fake Token": "伪造令牌",
        "Double Report": "双重上报"
    }
    cn_categories = [category_names.get(c, c) for c in categories]
    
                        
    display_rates = [r if r > 0 else 2 for r in rates]
    colors = ['#70AD47' if c == 'Honest' else '#E74C3C' for c in categories]
    
    x = np.arange(len(cn_categories))
    bars1 = ax1.bar(x, display_rates, color=colors, alpha=0.85, edgecolor='black', linewidth=1.2, width=0.7)
    
            
    bars1[0].set_linewidth(2.5)
    bars1[0].set_edgecolor('darkgreen')
    
                            
    for i, r in enumerate(rates):
        if r == 0:
            bars1[i].set_hatch('///')
            bars1[i].set_alpha(0.5)
    
    ax1.set_ylabel('接受率 (%)', fontsize=12, fontweight='bold')
    ax1.set_title('(a) 不同类型报告的接受率', fontsize=12, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(cn_categories, rotation=18, ha='right', fontsize=10)
    ax1.set_ylim(0, 108)
    ax1.grid(True, alpha=0.3, axis='y', linestyle='--')
    
          
    for i, (v, dv) in enumerate(zip(rates, display_rates)):
        if v > 5:
            ax1.text(i, dv/2, f'{v:.1f}%', ha='center', va='center', fontsize=11, fontweight='bold', color='white')
        elif v > 0:
            ax1.text(i, dv + 2, f'{v:.2f}%', ha='center', va='bottom', fontsize=11, fontweight='bold')
        else:
                           
            ax1.text(i, dv + 1.5, '0.00%\n(被拒绝)', ha='center', va='bottom', 
                    fontsize=10, fontweight='bold', color='#E74C3C',
                    bbox=dict(boxstyle='round,pad=0.3', facecolor='white', edgecolor='#E74C3C', linewidth=1.5))
    
          
    ax1.text(0.02, 0.98, '注: 斜线填充表示0%（为可见性设为2%高度）', 
            transform=ax1.transAxes, fontsize=9, verticalalignment='top',
            bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.8))
    
                        
    metrics = ['检测率', '误报率']
    values = [
        exp3["detection_metrics"]["detection_rate"],
        exp3["detection_metrics"]["false_positive_rate"]
    ]
    
                        
    display_values = [v if v > 0 else 4 for v in values]
    
    x2 = np.arange(len(metrics))
    colors2 = ['#70AD47', '#FFC000']
    bars2 = ax2.bar(x2, display_values, color=colors2, alpha=0.85, edgecolor='black', linewidth=1.2, width=0.5)
    
                  
    for i, v in enumerate(values):
        if v == 0:
            bars2[i].set_hatch('////')
            bars2[i].set_alpha(0.5)
            bars2[i].set_linewidth(2.0)
    
    ax2.set_ylabel('比率 (%)', fontsize=12, fontweight='bold')
    ax2.set_title('(b) 链接标签检测性能', fontsize=12, fontweight='bold')
    ax2.set_xticks(x2)
    ax2.set_xticklabels(metrics, fontsize=11)
    ax2.set_ylim(0, 108)
    ax2.grid(True, alpha=0.3, axis='y', linestyle='--')
    
          
    for i, (v, dv) in enumerate(zip(values, display_values)):
        if v > 5:
            ax2.text(i, dv/2, f'{v:.2f}%', ha='center', va='center', fontsize=12, fontweight='bold', color='white')
        elif v > 0:
            ax2.text(i, dv + 2, f'{v:.2f}%', ha='center', va='bottom', fontsize=12, fontweight='bold')
        else:
                   
            ax2.text(i, dv + 1.5, '0.00%\n(无误报)', ha='center', va='bottom', 
                    fontsize=11, fontweight='bold', color='#FFA500',
                    bbox=dict(boxstyle='round,pad=0.4', facecolor='white', edgecolor='#FFA500', linewidth=1.5))
    
          
    ax2.text(0.02, 0.98, '注: 斜线填充表示0%（为可见性设为4%高度）', 
            transform=ax2.transAxes, fontsize=9, verticalalignment='top',
            bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.8))
    
    plt.tight_layout()
    plt.savefig(output_dir / "图4_安全性验证.pdf", dpi=300, bbox_inches='tight')
    plt.savefig(output_dir / "图4_安全性验证.png", dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ 图4: 安全性验证")


def generate_fig5_comparative(data, output_dir):
    """图5: 对比方案性能 (柱状图)"""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    exp4 = data['experiment4_comparative']
    schemes = list(exp4["schemes"].keys())
    times = [exp4["schemes"][s]["vehicle_time_ms"] for s in schemes]
    
            
    scheme_names = {
        "PCVCS": "PCVCS\n(本方案)",
        "LA-SPR": "LA-SPR\n位置认证",
        "PPRM": "PPRM\n声誉证明",
        "PRVB": "PRVB\n区块链聚合",
        "FAIR": "FAIR\n同态加密",
        "SS-TA": "SS-TA\n秘密分享"
    }
    cn_schemes = [scheme_names.get(s, s) for s in schemes]
    
    x = np.arange(len(cn_schemes))
    
                                 
    colors = []
    for s, t in zip(schemes, times):
        if s == 'PCVCS':
            colors.append('#C55A11')        
        elif s == 'FAIR':
            colors.append('#ED7D31')             
        elif t < 5:
            colors.append('#70AD47')             
        else:
            colors.append('#4472C4')             
    
    bars = ax.bar(x, times, color=colors, alpha=0.85, edgecolor='black', linewidth=1.2, width=0.7)
    
           
    bars[0].set_linewidth(3)
    bars[0].set_edgecolor('darkred')
    
    ax.set_xlabel('方案', fontsize=12)
    ax.set_ylabel('车辆端计算时间 (ms)', fontsize=12)
    ax.set_title('不同方案的车辆端计算时间对比', fontsize=13, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(cn_schemes, fontsize=10)
    ax.grid(True, alpha=0.3, axis='y', linestyle='--')
    ax.set_ylim(0, max(times) * 1.2)
    
          
    for i, v in enumerate(times):
        ax.text(i, v + max(times)*0.02, f'{v:.2f}', ha='center', va='bottom', 
                fontsize=10, fontweight='bold')
    
          
    ax.text(0.98, 0.97, '* PCVCS为本方案\n* 数值越小越好', 
            transform=ax.transAxes, fontsize=9, 
            verticalalignment='top', horizontalalignment='right',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.3))
    
    plt.tight_layout()
    plt.savefig(output_dir / "图5_对比方案性能.pdf", dpi=300, bbox_inches='tight')
    plt.savefig(output_dir / "图5_对比方案性能.png", dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ 图5: 对比方案性能")


def generate_fig6_communication_comparison(data, output_dir):
    """图6: 通信开销对比 (新增)"""
    import matplotlib.pyplot as plt
    import numpy as np
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    exp5 = data['experiment5_communication_comparison']
    schemes = list(exp5["schemes"].keys())
    sizes_kb = [exp5["schemes"][s]["size_kb"] for s in schemes]
    
            
    scheme_names = {
        "SS-TA": "SS-TA\n秘密分享",
        "PRVB": "PRVB\n区块链",
        "PPRM": "PPRM\n声誉证明",
        "LA-SPR": "LA-SPR\n位置认证",
        "FAIR": "FAIR\n同态加密",
        "PCVCS": "PCVCS\n(本方案)"
    }
    cn_schemes = [scheme_names.get(s, s) for s in schemes]
    
    x = np.arange(len(cn_schemes))
    
          
    colors = []
    for s, size in zip(schemes, sizes_kb):
        if s == 'PCVCS':
            colors.append('#C55A11')        
        elif size < 1:        
            colors.append('#70AD47')      
        elif size > 4:       
            colors.append('#ED7D31')      
        else:
            colors.append('#4472C4')      
    
    bars = ax.bar(x, sizes_kb, color=colors, alpha=0.85, edgecolor='black', linewidth=1.2, width=0.7)
    
             
    for i, s in enumerate(schemes):
        if s == 'PCVCS':
            bars[i].set_linewidth(3)
            bars[i].set_edgecolor('darkred')
    
    ax.set_xlabel('方案', fontsize=12)
    ax.set_ylabel('报告大小 (KB)', fontsize=12)
    ax.set_title('各方案单条报告大小对比', fontsize=13, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(cn_schemes, fontsize=10)
    ax.grid(True, alpha=0.3, axis='y', linestyle='--')
    ax.set_ylim(0, max(sizes_kb) * 1.2)
    
          
    for i, v in enumerate(sizes_kb):
        ax.text(i, v + max(sizes_kb)*0.02, f'{v:.2f}', ha='center', va='bottom', 
                fontsize=10, fontweight='bold')
    
          
    ax.text(0.98, 0.97, '* PCVCS为本方案\n* 基于协议格式静态分析', 
            transform=ax.transAxes, fontsize=9, 
            verticalalignment='top', horizontalalignment='right',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.3))
    
    plt.tight_layout()
    plt.savefig(output_dir / "图6_通信开销对比.pdf", dpi=300, bbox_inches='tight')
    plt.savefig(output_dir / "图6_通信开销对比.png", dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ 图6: 通信开销对比")


def generate_fig7_anonymity_strength(data, output_dir):
    """图7: 匿名性强度对比 (柱状图)"""
    import matplotlib.pyplot as plt
    import numpy as np
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    
    exp6 = data['experiment6_anonymity_strength_comparison']
    schemes = list(exp6["schemes"].keys())
    
            
    scheme_names_cn = {
        "SS-TA": "SS-TA",
        "PRVB": "PRVB",
        "PPRM": "PPRM",
        "LA-SPR": "LA-SPR",
        "FAIR": "FAIR",
        "PCVCS": "PCVCS\n(本方案)"
    }
    cn_schemes = [scheme_names_cn.get(s, s) for s in schemes]
    
          
    tracking_probs = [exp6["schemes"][s]["tracking_probability"] * 100 for s in schemes]         
    anonymity_sets = [exp6["schemes"][s]["anonymity_set_size"] for s in schemes]
    
                      
    x = np.arange(len(schemes))
    colors = ['#E74C3C', '#F39C12', '#F39C12', '#E67E22', '#E67E22', '#27AE60']
    bars1 = ax1.bar(x, tracking_probs, color=colors, edgecolor='black', linewidth=1.2)
    
                     
    bars1[-1].set_color('#2ECC71')
    bars1[-1].set_linewidth(2.5)
    bars1[-1].set_edgecolor('#196F3D')
    
    ax1.set_ylabel('被追踪概率 (%)', fontsize=12, fontweight='bold')
    ax1.set_xlabel('方案', fontsize=12, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(cn_schemes, fontsize=10)
    ax1.set_ylim(0, max(tracking_probs) * 1.15)
    ax1.grid(axis='y', alpha=0.3, linestyle='--')
    
          
    for i, (bar, val) in enumerate(zip(bars1, tracking_probs)):
        if val >= 10:
            ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height()/2,
                    f'{val:.0f}%', ha='center', va='center',
                    fontsize=11, fontweight='bold', color='white')
        else:
            ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(tracking_probs)*0.03,
                    f'{val:.0f}%', ha='center', va='bottom',
                    fontsize=11, fontweight='bold')
    
          
    ax1.text(0.5, 0.97, '(更低更好)', transform=ax1.transAxes,
            ha='center', va='top', fontsize=10, style='italic',
            bbox=dict(boxstyle='round,pad=0.4', facecolor='lightyellow', alpha=0.8))
    
                       
    bars2 = ax2.bar(x, anonymity_sets, color=colors, edgecolor='black', linewidth=1.2)
    
               
    bars2[-1].set_color('#2ECC71')
    bars2[-1].set_linewidth(2.5)
    bars2[-1].set_edgecolor('#196F3D')
    
    ax2.set_ylabel('匿名集合大小（车辆数）', fontsize=12, fontweight='bold')
    ax2.set_xlabel('方案', fontsize=12, fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(cn_schemes, fontsize=10)
    ax2.set_ylim(0, max(anonymity_sets) * 1.15)
    ax2.grid(axis='y', alpha=0.3, linestyle='--')
    
          
    for i, (bar, val) in enumerate(zip(bars2, anonymity_sets)):
        if val >= 10:
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height()/2,
                    f'{val}', ha='center', va='center',
                    fontsize=11, fontweight='bold', color='white')
        else:
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(anonymity_sets)*0.03,
                    f'{val}', ha='center', va='bottom',
                    fontsize=11, fontweight='bold')
    
          
    ax2.text(0.5, 0.97, '(更大更好)', transform=ax2.transAxes,
            ha='center', va='top', fontsize=10, style='italic',
            bbox=dict(boxstyle='round,pad=0.4', facecolor='lightyellow', alpha=0.8))
    
            
    explanation = (
        "指标定义: 最坏情况下，攻击者成功把一条上报链接到具体车辆的概率\n"
        "PCVCS使用LSAG环签名（环大小=50），提供最大匿名集合和最低被追踪概率"
    )
    fig.text(0.5, 0.02, explanation, ha='center', fontsize=10,
            bbox=dict(boxstyle='round,pad=0.8', facecolor='lightyellow',
                     edgecolor='gray', linewidth=1.5, alpha=0.9))
    
    plt.tight_layout(rect=[0, 0.08, 1, 1])
    plt.savefig(output_dir / "图7_匿名性强度对比.pdf", dpi=300, bbox_inches='tight')
    plt.savefig(output_dir / "图7_匿名性强度对比.png", dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ 图7: 匿名性强度对比")


def main():
               
    results_base = Path("performance_evaluation_results")
    latest_dir = max(results_base.iterdir(), key=lambda p: p.stat().st_mtime)
    
    data_dir = latest_dir / "raw_data"
    output_dir = latest_dir / "figures_chinese"
    output_dir.mkdir(exist_ok=True)
    
    print("=" * 70)
    print("生成中文版性能评估图表")
    print("=" * 70)
    print(f"数据目录: {data_dir}")
    print(f"输出目录: {output_dir}")
    print()
    
          
    data = load_data(data_dir)
    
            
    generate_fig1_client_breakdown(data, output_dir)
    generate_fig2_server_breakdown(data, output_dir)
    generate_fig3_communication(data, output_dir)
    generate_fig4_security(data, output_dir)
    generate_fig5_comparative(data, output_dir)
    generate_fig6_communication_comparison(data, output_dir)
    generate_fig7_anonymity_strength(data, output_dir)
    
    print()
    print("=" * 70)
    print("✅ 所有中文图表生成完成!")
    print(f"保存位置: {output_dir}")
    print("=" * 70)


if __name__ == "__main__":
    main()
