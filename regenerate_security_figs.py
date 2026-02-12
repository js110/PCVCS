                      
                       
import sys
import json
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np


def style_for_ieee():
    plt.rcParams.update({
        'font.size': 10,
        'font.family': 'serif',
        'axes.linewidth': 0.8,
        'axes.grid': True,
        'grid.linestyle': '--',
        'grid.alpha': 0.25
    })


def generate_acceptance_rate(data, out_path):
    acc = data['acceptance_rates']
    labels = list(acc.keys())
    values = [acc[k] for k in labels]

    style_for_ieee()

    fig, ax = plt.subplots(figsize=(6, 4))

    x = np.arange(len(labels))
                                                                   
    fills = ['#4CAF50' if v >= 50 else '#E57373' for v in values]
    hatches = ['' if v >= 50 else '///' for v in values]

    bars = []
    for xi, v, fc, hatch in zip(x, values, fills, hatches):
        bar = ax.bar(xi, v, color=fc, edgecolor='black', linewidth=0.8, hatch=hatch)
        bars.append(bar)

                                                                           
    ylim_top = max(105, max(values) * 1.12)
    ax.set_ylim(0, ylim_top)
    for xi, v in zip(x, values):
        if v >= 8:
            ax.text(xi, v/2, f'{v:.1f}%', ha='center', va='center', color='white', fontsize=9, fontweight='bold')
        else:
                                                                             
            y_text = v + 0.03 * (ylim_top)
            ax.text(xi, y_text, f'{v:.2f}%\n(Rejected)', ha='center', va='bottom', fontsize=8, color='black', bbox=dict(boxstyle='round,pad=0.2', facecolor='white', edgecolor='black'))

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=20, ha='right')
    ax.set_ylabel('Acceptance Rate (%)')

    plt.tight_layout()
    out_path.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path / 'Fig_Security_Acceptance_Rate.pdf', dpi=300, bbox_inches='tight')
    plt.savefig(out_path / 'Fig_Security_Acceptance_Rate.png', dpi=300, bbox_inches='tight')
    plt.close()


def generate_detection_metrics(data, out_path):
    metrics = data['detection_metrics']
    keys = ['detection_rate', 'false_positive_rate']
    labels = ['Detection Rate', 'False Positive Rate']
    values = [metrics[k] for k in keys]

    style_for_ieee()

    fig, ax = plt.subplots(figsize=(6, 4))

    x = np.arange(len(labels))
                                                                           
    fills = ['#388E3C', '#BDBDBD']
    hatches = ['', '///']
    bars = []
    for xi, v, fc, hatch in zip(x, values, fills, hatches):
        bars.append(ax.bar(xi, v, color=fc, edgecolor='black', linewidth=0.8, hatch=hatch))

                                                         
    ylim_top = max(105, max(values) * 1.12)
    ax.set_ylim(0, ylim_top)

                                                                                         
    for xi, v in zip(x, values):
                                                                     
        if v >= 8:
            ax.text(xi, v/2, f'{v:.1f}%', ha='center', va='center', fontsize=10, fontweight='bold', color='white')
        else:
            y_text = v + 0.02 * (ylim_top)
            ax.text(xi, y_text, f'{v:.2f}%' if v < 1 else f'{v:.1f}%', ha='center', va='bottom', fontsize=10, fontweight='bold', color='black')

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel('Rate (%)')

    plt.tight_layout()
    out_path.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path / 'Fig_Security_Detection_Metrics.pdf', dpi=300, bbox_inches='tight')
    plt.savefig(out_path / 'Fig_Security_Detection_Metrics.png', dpi=300, bbox_inches='tight')
    plt.close()


def generate_security_combined(data, out_path):
    acc = data['acceptance_rates']
    acc_labels = list(acc.keys())
    acc_values = [acc[k] for k in acc_labels]

    metrics = data['detection_metrics']
    det_keys = ['detection_rate', 'false_positive_rate']
    det_labels = ['Detection Rate', 'False Positive Rate']
    det_values = [metrics[k] for k in det_keys]

    style_for_ieee()
    fig, axs = plt.subplots(1, 2, figsize=(10, 4.5))

                            
    ax = axs[0]
    x = np.arange(len(acc_labels))
    fills = ['#4CAF50' if v >= 50 else '#E57373' for v in acc_values]
    hatches = ['' if v >= 50 else '///' for v in acc_values]
    for xi, v, fc, hatch in zip(x, acc_values, fills, hatches):
        ax.bar(xi, v, color=fc, edgecolor='black', linewidth=0.8, hatch=hatch)

    ylim_top = max(105, max(acc_values) * 1.12)
    ax.set_ylim(0, ylim_top)
    for xi, v in zip(x, acc_values):
        if v >= 8:
            ax.text(xi, v/2, f'{v:.1f}%', ha='center', va='center', color='white', fontsize=9, fontweight='bold')
        else:
            y_text = v + 0.03 * (ylim_top)
            ax.text(xi, y_text, f'{v:.2f}%\n(Rejected)', ha='center', va='bottom', fontsize=8, color='black', bbox=dict(boxstyle='round,pad=0.2', facecolor='white', edgecolor='black'))

    ax.set_xticks(x)
    ax.set_xticklabels(acc_labels, rotation=20, ha='right')
    ax.set_ylabel('Acceptance Rate (%)')
    ax.text(-0.12, 1.06, '(a)', transform=ax.transAxes, fontsize=12, fontweight='bold')

                              
    ax = axs[1]
    x = np.arange(len(det_labels))
    fills = ['#388E3C', '#BDBDBD']
    hatches = ['', '///']
    for xi, v, fc, hatch in zip(x, det_values, fills, hatches):
        ax.bar(xi, v, color=fc, edgecolor='black', linewidth=0.8, hatch=hatch)

    ylim_top = max(105, max(det_values) * 1.12)
    ax.set_ylim(0, ylim_top)
    for xi, v in zip(x, det_values):
        if v >= 8:
            ax.text(xi, v/2, f'{v:.1f}%', ha='center', va='center', fontsize=10, fontweight='bold', color='white')
        else:
            y_text = v + 0.02 * (ylim_top)
            ax.text(xi, y_text, f'{v:.2f}%' if v < 1 else f'{v:.1f}%', ha='center', va='bottom', fontsize=10, fontweight='bold', color='black')

    ax.set_xticks(x)
    ax.set_xticklabels(det_labels)
    ax.set_ylabel('Rate (%)')
    ax.text(-0.12, 1.06, '(b)', transform=ax.transAxes, fontsize=12, fontweight='bold')

    plt.tight_layout()
    out_path.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path / 'Fig_Security_Combined_fromdata.pdf', dpi=300, bbox_inches='tight')
    plt.savefig(out_path / 'Fig_Security_Combined_fromdata.png', dpi=300, bbox_inches='tight')
    plt.close()


def main():
    if len(sys.argv) > 1:
        results_dir = Path(sys.argv[1])
    else:
        results_dir = Path('performance_evaluation_results') / '20251206_153158'

    raw_file = results_dir / 'raw_data' / 'experiment3_security.json'
    out_dir = results_dir / 'figures_fromdata'

    if not raw_file.exists():
        print(f'ERROR: data file not found: {raw_file}')
        return

    with open(raw_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

                                             
                                               
                                                            
    generate_security_combined(data, out_dir)
    print(f'Generated security figures in: {out_dir}')


if __name__ == '__main__':
    main()
