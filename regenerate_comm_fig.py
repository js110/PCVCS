                      
                       
"""
Regenerate communication/report-size figure (improved styling, no title).
Usage: python regenerate_comm_fig.py <results_dir>
"""
import sys
import json
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np


def style_clean():
    plt.rcParams.update({
        'font.size': 10,
        'font.family': 'serif',
        'axes.linewidth': 0.8,
        'axes.grid': True,
        'grid.linestyle': '--',
        'grid.alpha': 0.25
    })


def generate_report_size(data, out_path):
    entries = data['report_sizes']
                                                                 
    entries = entries[:3]
    leaf_counts = [e['leaf_count'] for e in entries]
    sizes_kb = [e['size_kb'] for e in entries]

    style_clean()
    fig, ax = plt.subplots(figsize=(9, 4.5))

                                                                 
    ax.plot(leaf_counts, sizes_kb, marker='o', linewidth=2.5, markersize=10,
            color='#4472C4', markerfacecolor='white', markeredgewidth=2.5, label='PCVCS (Merkle Tree)', zorder=3)

                                                                         
    c0 = 6.0
    naive_sizes_kb = [c0 + (8 * n / 1024) for n in leaf_counts]
    ax.plot(leaf_counts, naive_sizes_kb, marker='s', linewidth=2.5, markersize=9,
            color='#FF6B35', linestyle='--', markerfacecolor='white', markeredgewidth=2.5, markeredgecolor='#FF6B35',
            label='Naive (List Encoding)', alpha=0.9, zorder=2)

    ax.set_xscale('log', base=2)
    ax.set_xticks(leaf_counts)
    ax.set_xticklabels([f'{n:,}' for n in leaf_counts], fontsize=10)

    ax.set_xlabel('Number of Authorized Cells $|A_\\tau|$', fontsize=11)
    ax.set_ylabel('Report Size (KB)', fontsize=11)
                               

    ax.legend(loc='upper left', framealpha=0.95, fontsize=10, edgecolor='black', fancybox=True)

    ax.grid(True, alpha=0.3, linestyle='--', which='both')
    ax.set_ylim(0, max(max(sizes_kb), max(naive_sizes_kb)) * 1.15)

                                                        
    for n, s in zip(leaf_counts, sizes_kb):
        ax.text(n, s + max(naive_sizes_kb)*0.015, f'{s:.2f}', ha='center', va='bottom', fontsize=9, color='#4472C4', fontweight='bold')
                                                 
    for n, s in zip(leaf_counts, naive_sizes_kb):
        ax.text(n, s + max(naive_sizes_kb)*0.015, f'{s:.1f}', ha='center', va='bottom', fontsize=9, color='#FF6B35', fontweight='bold')

    plt.tight_layout()
    out_path.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path / 'Fig_Comm_ReportSize_fromdata.pdf', dpi=300, bbox_inches='tight')
    plt.savefig(out_path / 'Fig_Comm_ReportSize_fromdata.png', dpi=300, bbox_inches='tight')
    plt.close()


def main():
    if len(sys.argv) > 1:
        results_dir = Path(sys.argv[1])
    else:
        results_dir = Path('performance_evaluation_results') / '20251206_153158'

    raw_file = results_dir / 'raw_data' / 'experiment2_communication.json'
    out_dir = results_dir / 'figures_fromdata'

    if not raw_file.exists():
        print(f'ERROR: data file not found: {raw_file}')
        return

    with open(raw_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    generate_report_size(data, out_dir)
    print(f'Generated communication figure in: {out_dir}')


if __name__ == '__main__':
    main()
