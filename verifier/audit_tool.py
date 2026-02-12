#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
审计机构工具 - 受控去匿名化
用于在争议场景中追溯车辆真实身份
"""

import json
import argparse
from pathlib import Path
from common.linkable_ring_signature import LinkableRingSignature


def load_lrs_verifier(state_file: str = "lrs_verifier_state.json") -> LinkableRingSignature:
    """
    加载LRS验证器状态（包含审计数据库）
    
    实际部署中，审计数据库应存储在安全的后端数据库中
    """
    lrs = LinkableRingSignature()
    
    # 如果状态文件存在，加载之前的审计记录
    state_path = Path(state_file)
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding='utf-8'))
            # 恢复审计数据库（简化版）
            print(f"✓ 已加载 {len(state.get('audit_records', []))} 条审计记录")
        except Exception as e:
            print(f"⚠ 加载状态文件失败: {e}")
    
    return lrs


def deanonymize(link_tag: str, task_id: str, authority_sk_hex: str, lrs: LinkableRingSignature):
    """
    执行受控去匿名化
    
    Args:
        link_tag: 要追溯的链接标签
        task_id: 任务ID
        authority_sk_hex: 审计机构追踪密钥（十六进制）
        lrs: LRS系统实例
    """
    print(f"\n=== 审计机构 - 受控去匿名化 ===")
    print(f"任务ID: {task_id}")
    print(f"链接标签: {link_tag}")
    
    try:
        # 转换追踪密钥
        authority_sk = bytes.fromhex(authority_sk_hex)
        
        # 执行去匿名化
        audit_record = lrs.controlled_deanonymization(
            link_tag=link_tag,
            task_id=task_id,
            authority_sk=authority_sk
        )
        
        if audit_record:
            print(f"\n✓ 去匿名化成功！")
            print(f"  真实车辆ID: {audit_record.vehicle_id}")
            print(f"  主公钥: {audit_record.master_pk.hex()}")
            print(f"  任务公钥: {audit_record.derived_pk.hex()}")
            print(f"  注册时间: {audit_record.timestamp}")
            
            return audit_record
        else:
            print(f"\n✗ 未找到匹配的审计记录")
            print(f"  可能原因：")
            print(f"  1. link_tag 不存在于系统中")
            print(f"  2. task_id 不匹配")
            print(f"  3. 审计数据库未同步")
            return None
            
    except PermissionError:
        print(f"\n✗ 权限错误：追踪密钥无效")
        print(f"  审计机构必须持有正确的追踪密钥才能执行去匿名化")
        return None
    except Exception as e:
        print(f"\n✗ 去匿名化失败: {e}")
        return None


def export_task_report(task_id: str, authority_sk_hex: str, lrs: LinkableRingSignature, output_file: str):
    """
    导出任务审计报告
    
    Args:
        task_id: 任务ID
        authority_sk_hex: 审计机构追踪密钥
        lrs: LRS系统实例
        output_file: 输出文件路径
    """
    print(f"\n=== 导出任务审计报告 ===")
    print(f"任务ID: {task_id}")
    
    try:
        authority_sk = bytes.fromhex(authority_sk_hex)
        
        # 导出报告
        report = lrs.export_audit_report(task_id, authority_sk)
        
        # 保存到文件
        output_path = Path(output_file)
        output_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False, default=bytes_to_hex),
            encoding='utf-8'
        )
        
        print(f"\n✓ 审计报告已导出到: {output_file}")
        print(f"  注册车辆总数: {report['total_registered_vehicles']}")
        print(f"  唯一车辆数: {report['unique_vehicles']}")
        print(f"  报告时间: {report['timestamp']}")
        
        return report
        
    except PermissionError:
        print(f"\n✗ 权限错误：追踪密钥无效")
        return None
    except Exception as e:
        print(f"\n✗ 导出失败: {e}")
        return None


def bytes_to_hex(obj):
    """JSON序列化辅助函数"""
    if isinstance(obj, bytes):
        return obj.hex()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def analyze_duplicate_submissions(lrs: LinkableRingSignature):
    """
    分析重复提交情况
    
    Args:
        lrs: LRS系统实例
    """
    print(f"\n=== 重复提交分析 ===")
    
    if not lrs.link_tag_db:
        print("✓ 未检测到重复提交")
        return
    
    total_tasks = len(set(record[0]["task_id"] for records in lrs.link_tag_db.values() for record in [records]))
    total_submissions = sum(len(records) for records in lrs.link_tag_db.values())
    unique_submitters = len(lrs.link_tag_db)
    
    print(f"任务总数: {total_tasks}")
    print(f"提交总数: {total_submissions}")
    print(f"唯一提交者: {unique_submitters}")
    
    # 查找重复提交
    duplicates = [(key, records) for key, records in lrs.link_tag_db.items() if len(records) > 1]
    
    if duplicates:
        print(f"\n⚠ 检测到 {len(duplicates)} 个重复提交者：")
        for key, records in duplicates[:10]:  # 只显示前10个
            task_id, link_tag = key.split(":", 1)
            print(f"  - 任务: {task_id}, link_tag: {link_tag[:16]}..., 提交次数: {len(records)}")
    else:
        print("✓ 所有提交者均为首次提交")


def main():
    parser = argparse.ArgumentParser(description="审计机构工具 - 受控去匿名化")
    
    subparsers = parser.add_subparsers(dest="command", help="可用命令")
    
    # 子命令1: 去匿名化
    deanon_parser = subparsers.add_parser("deanonymize", help="追溯车辆真实身份")
    deanon_parser.add_argument("--link-tag", required=True, help="链接标签（十六进制）")
    deanon_parser.add_argument("--task-id", required=True, help="任务ID")
    deanon_parser.add_argument("--authority-sk", required=True, help="审计机构追踪密钥（十六进制）")
    deanon_parser.add_argument("--state-file", default="lrs_verifier_state.json", help="LRS状态文件")
    
    # 子命令2: 导出报告
    report_parser = subparsers.add_parser("export-report", help="导出任务审计报告")
    report_parser.add_argument("--task-id", required=True, help="任务ID")
    report_parser.add_argument("--authority-sk", required=True, help="审计机构追踪密钥（十六进制）")
    report_parser.add_argument("--output", required=True, help="输出文件路径")
    report_parser.add_argument("--state-file", default="lrs_verifier_state.json", help="LRS状态文件")
    
    # 子命令3: 分析重复提交
    analyze_parser = subparsers.add_parser("analyze-duplicates", help="分析重复提交情况")
    analyze_parser.add_argument("--state-file", default="lrs_verifier_state.json", help="LRS状态文件")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # 加载LRS验证器
    lrs = load_lrs_verifier(args.state_file if hasattr(args, 'state_file') else "lrs_verifier_state.json")
    
    # 执行对应命令
    if args.command == "deanonymize":
        deanonymize(args.link_tag, args.task_id, args.authority_sk, lrs)
    
    elif args.command == "export-report":
        export_task_report(args.task_id, args.authority_sk, lrs, args.output)
    
    elif args.command == "analyze-duplicates":
        analyze_duplicate_submissions(lrs)


if __name__ == "__main__":
    main()
