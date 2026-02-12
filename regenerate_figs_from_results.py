                      
                       
"""
Regenerate figures from an existing performance_evaluation_results run
Usage: python regenerate_figs_from_results.py <results_dir>
If no dir is given, defaults to `performance_evaluation_results/20251206_153158`.
"""
import sys
import json
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np


def generate_client_breakdown(data, out_path):
    ring_sizes = data["ring_sizes"]
    breakdown = data["client_breakdown"]

    setup = [item["commitments_setup"] for item in breakdown]
    zk = [item["spatio_temporal_zk"] for item in breakdown]
    lsag = [item["lsag_signing"] for item in breakdown]
    kem = [item["ml_kem_encryption"] for item in breakdown]

    fig, ax = plt.subplots(figsize=(12, 6))
    x = np.arange(len(ring_sizes))
    width = 0.2

    bars1 = ax.bar(x - 1.5*width, setup, width, label='Commitments & Setup',
                   color='#FFC000', edgecolor='black', linewidth=1, hatch='/')
    bars2 = ax.bar(x - 0.5*width, zk, width, label='Spatio-Temporal ZK',
                   color='#4472C4', edgecolor='black', linewidth=1, hatch='\\')
    bars3 = ax.bar(x + 0.5*width, lsag, width, label='LSAG Signing',
                   color='#ED7D31', edgecolor='black', linewidth=1, hatch='x')
    bars4 = ax.bar(x + 1.5*width, kem, width, label='ML-KEM Encryption',
                   color='#70AD47', edgecolor='black', linewidth=1, hatch='.')

    for i, (s, z, l, k) in enumerate(zip(setup, zk, lsag, kem)):
        ax.text(i - 1.5*width, s + 0.2, f'{s:.1f}', ha='center', va='bottom', fontsize=7)
        ax.text(i - 0.5*width, z + 0.2, f'{z:.1f}', ha='center', va='bottom', fontsize=7)
        ax.text(i + 0.5*width, l + 0.2, f'{l:.1f}', ha='center', va='bottom', fontsize=7)
        ax.text(i + 1.5*width, k + 0.2, f'{k:.1f}', ha='center', va='bottom', fontsize=7)

    ax.set_xlabel('Ring Size $n_R$', fontsize=11)
    ax.set_ylabel('Time (ms)', fontsize=11)
    ax.set_xticks(x)
    ax.set_xticklabels(ring_sizes)
    ax.legend(loc='upper right', bbox_to_anchor=(0.98, 0.98), ncol=2, framealpha=0.9,
              fontsize=10, edgecolor='black', fancybox=True)
    ax.grid(True, alpha=0.3, axis='y', linestyle='--')
    ax.set_ylim(0, max(max(zk), max(lsag), max(kem)) * 1.25)

                                     

    plt.tight_layout()
    out_path.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path / "Fig_Exp1_Client_Breakdown_fromdata.pdf", dpi=300, bbox_inches='tight')
    plt.savefig(out_path / "Fig_Exp1_Client_Breakdown_fromdata.png", dpi=300, bbox_inches='tight')
    plt.close()


def generate_server_breakdown(data, out_path):
    ring_sizes = data["ring_sizes"]
    breakdown = data["server_breakdown"]

    zk_ver = [item["zk_verification"] for item in breakdown]
    lrs_ver = [item["lrs_verification"] for item in breakdown]
    kem_dec = [item["kem_decapsulation"] for item in breakdown]

    fig, ax = plt.subplots(figsize=(11, 6))
    x = np.arange(len(ring_sizes))
    width = 0.25

    bars1 = ax.bar(x - width, zk_ver, width, label='ZK Verification',
                   color='#4472C4', edgecolor='black', linewidth=1, hatch='\\')
    bars2 = ax.bar(x, lrs_ver, width, label='Ring Signature Verification',
                   color='#ED7D31', edgecolor='black', linewidth=1, hatch='x')
    bars3 = ax.bar(x + width, kem_dec, width, label='KEM Decapsulation',
                   color='#70AD47', edgecolor='black', linewidth=1, hatch='.')

    for i, (z, l, k) in enumerate(zip(zk_ver, lrs_ver, kem_dec)):
        ax.text(i - width, z + 0.15, f'{z:.1f}', ha='center', va='bottom', fontsize=8)
        ax.text(i, l + 0.15, f'{l:.1f}', ha='center', va='bottom', fontsize=8)
        ax.text(i + width, k + 0.15, f'{k:.1f}', ha='center', va='bottom', fontsize=8)

    ax.set_xlabel('Ring Size $n_R$', fontsize=11)
    ax.set_ylabel('Time (ms)', fontsize=11)
    ax.set_xticks(x)
    ax.set_xticklabels(ring_sizes)
    ax.legend(loc='upper right', bbox_to_anchor=(0.98, 0.98), ncol=2, framealpha=0.9,
              fontsize=10, edgecolor='black', fancybox=True)
    ax.grid(True, alpha=0.3, axis='y', linestyle='--')
    ax.set_ylim(0, max(max(zk_ver), max(lrs_ver), max(kem_dec)) * 1.25)

                                     

    plt.tight_layout()
    out_path.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path / "Fig_Exp1_Server_Breakdown_fromdata.pdf", dpi=300, bbox_inches='tight')
    plt.savefig(out_path / "Fig_Exp1_Server_Breakdown_fromdata.png", dpi=300, bbox_inches='tight')
    plt.close()


def main():
    if len(sys.argv) > 1:
        results_dir = Path(sys.argv[1])
    else:
        results_dir = Path('performance_evaluation_results') / '20251206_153158'

    raw_file = results_dir / 'raw_data' / 'experiment1_micro_benchmark.json'
    figs_dir = results_dir / 'figures_fromdata'

    if not raw_file.exists():
        print(f"ERROR: data file not found: {raw_file}")
        return

    with open(raw_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    generate_client_breakdown(data, figs_dir)
    generate_server_breakdown(data, figs_dir)
    print(f"Figures generated in: {figs_dir}")


if __name__ == '__main__':
    main()
