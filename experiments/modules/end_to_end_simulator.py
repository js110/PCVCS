#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端到端仿真模块 - 集成真实SUMO仿真
"""

import os
import sys
import time
import json
import psutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from experiments.models.simulation_result import (
    SimulationResult, LatencyMetrics, ResourceMetrics, CommunicationMetrics,
    SimulationResultCollection
)
from experiments.logger import ExperimentLogger

# 导入密码学组件用于直接生成证明
from common.crypto import merkle_root, merkle_proof
from common.crypto_adapters import (
    ed25519_generate_keypair, ed25519_sign,
    range_proof_prove, range_proof_verify,
    lrs_sign, lrs_verify
)


class EndToEndSimulator:
    """端到端仿真器 - 集成SUMO"""
    
    def __init__(self, logger: Optional[ExperimentLogger] = None, sumo_home: str = "D:/sumo"):
        """
        初始化仿真器
        
        Args:
            logger: 日志记录器
            sumo_home: SUMO安装路径
        """
        self.logger = logger
        self.results = SimulationResultCollection()
        self.process = psutil.Process()
        self.sumo_home = Path(sumo_home)
        
        # 设置SUMO环境变量
        os.environ["SUMO_HOME"] = str(self.sumo_home)
        if (self.sumo_home / "tools").exists():
            sys.path.insert(0, str(self.sumo_home / "tools"))
        
        # SUMO配置文件路径 - 使用新的网络文件
        self.sumo_config_dir = project_root / "sumo"
        self.sumo_cfg = self.sumo_config_dir / "simple_test.cfg"  # 使用简单的测试配置
        
        # RSU位置（网格中的RSU）
        self.rsu_positions = "100,100; 200,200; 300,300; 400,400"
        
        # 数据目录
        self.data_dir = project_root / "data"
        self.data_dir.mkdir(exist_ok=True)
    
    def _log(self, message: str, level: str = "info") -> None:
        """记录日志"""
        if self.logger:
            getattr(self.logger, level)(message)
    
    def verify_sumo_installation(self) -> bool:
        """验证SUMO安装"""
        try:
            if not self.sumo_home.exists():
                self._log(f"SUMO路径不存在: {self.sumo_home}", "error")
                return False
            
            sumo_bin = self.sumo_home / "bin" / "sumo.exe"
            if not sumo_bin.exists():
                self._log(f"SUMO可执行文件不存在: {sumo_bin}", "error")
                return False
            
            self._log(f"SUMO安装验证成功: {self.sumo_home}")
            return True
            
        except Exception as e:
            self._log(f"SUMO验证失败: {e}", "error")
            return False
    
    def generate_trips_file(self, vehicle_count: int, duration: int) -> Path:
        """
        生成SUMO trips文件
        
        Args:
            vehicle_count: 车辆数量
            duration: 仿真时长（秒）
        
        Returns:
            trips文件路径
        """
        trips_file = self.sumo_config_dir / f"trips_{vehicle_count}v.trips.xml"
        
        # 生成trips XML
        trips_xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
        trips_xml += '<routes>\n'
        trips_xml += '  <vType id="car" accel="2.6" decel="4.5" sigma="0.5" length="5" maxSpeed="50"/>\n'
        
        # 定义可能的起点和终点边
        edges = ["gneE0", "gneE1", "gneE2", "gneE3", "gneE4", "gneE5", "gneE6", "gneE7", "gneE8",
                "gneE9", "gneE10", "gneE11", "gneE12", "gneE13", "gneE14", "gneE15", "gneE16", "gneE17"]
        
        # 为每辆车生成一个trip
        import random
        random.seed(42)  # 固定随机种子以保证可复现性
        
        for i in range(vehicle_count):
            depart_time = random.uniform(0, duration * 0.3)  # 在前30%的时间内出发
            from_edge = random.choice(edges)
            to_edge = random.choice([e for e in edges if e != from_edge])
            
            trips_xml += f'  <trip id="veh_{i}" depart="{depart_time:.2f}" from="{from_edge}" to="{to_edge}" type="car"/>\n'
        
        trips_xml += '</routes>\n'
        
        trips_file.write_text(trips_xml, encoding='utf-8')
        self._log(f"生成trips文件: {trips_file} ({vehicle_count}辆车)")
        
        return trips_file
    
    def run_sumo_simulation(self, scenario: Dict[str, Any]) -> Path:
        """
        运行SUMO仿真并生成RSU事件
        
        Args:
            scenario: 场景配置
        
        Returns:
            RSU事件文件路径
        """
        self._log(f"运行SUMO仿真: {scenario['name']}")
        
        # 生成trips文件
        trips_file = self.generate_trips_file(scenario['vehicles'], scenario['duration'])
        
        # 输出文件
        events_file = self.data_dir / f"scenario_{scenario['name']}_events.json"
        
        # 构建命令
        run_sumo_script = project_root / "sim" / "run_sumo_traci.py"
        
        cmd = [
            sys.executable,
            str(run_sumo_script),
            "--cfg", str(self.sumo_cfg),
            "--rsu", self.rsu_positions,
            "--window", "60",
            "--steps", str(scenario['duration']),
            "--out", str(events_file),
            "--collect-metrics"
        ]
        
        self._log(f"执行命令: {' '.join(cmd)}")
        
        try:
            # 设置环境变量，确保子进程能找到项目模块
            env = os.environ.copy()
            env['PYTHONPATH'] = str(project_root)
            
            # 运行SUMO仿真
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=scenario['duration'] + 300,  # 额外5分钟超时
                env=env
            )
            
            if result.returncode != 0:
                self._log(f"SUMO仿真失败: {result.stderr}", "error")
                raise RuntimeError(f"SUMO simulation failed: {result.stderr}")
            
            self._log(f"SUMO仿真完成: {events_file}")
            return events_file
            
        except subprocess.TimeoutExpired:
            self._log("SUMO仿真超时", "error")
            raise
        except Exception as e:
            self._log(f"SUMO仿真异常: {e}", "error")
            raise
    
    def measure_proof_generation_and_verification(self, events_file: Path, use_zkp: bool = True) -> Dict[str, Any]:
        """
        测量证明生成和验证性能
        
        Args:
            events_file: RSU事件文件
            use_zkp: 是否使用零知识证明
        
        Returns:
            性能指标字典
        """
        self._log(f"测量性能 (ZKP: {use_zkp})")
        
        # 加载事件数据
        with open(events_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        events = data.get("events", [])
        if not events:
            self._log("没有事件数据", "warning")
            return {
                "latencies": [],
                "packet_sizes": [],
                "success_count": 0,
                "failure_count": 0
            }
        
        # 白名单文件
        whitelist_file = self.data_dir / "whitelist_geohash.txt"
        
        # 加载白名单
        if whitelist_file.exists():
            with open(whitelist_file, 'r', encoding='utf-8') as f:
                whitelist = [line.strip() for line in f if line.strip()]
        else:
            whitelist = ["wtw3s8n", "wtw3s8p", "wtw3s8q", "wtw3s8r"]
        
        latencies = []
        packet_sizes = []
        success_count = 0
        failure_count = 0
        
        # 采样测试（避免测试所有事件）
        import random
        sample_size = min(100, len(events))
        sampled_events = random.sample(events, sample_size)
        
        for i, event in enumerate(sampled_events):
            try:
                # 创建临时事件文件
                temp_events_file = self.data_dir / f"temp_event_{i}.json"
                temp_packet_file = self.data_dir / f"temp_packet_{i}.json"
                
                # 保存单个事件
                temp_data = {
                    "rsus": data["rsus"],
                    "events": [event]
                }
                with open(temp_events_file, 'w', encoding='utf-8') as f:
                    json.dump(temp_data, f)
                
                # 测量证明生成时间
                gen_start = time.perf_counter()
                
                if use_zkp:
                    # 直接生成ZKP证明（不调用外部函数）
                    try:
                        # 1. Ed25519签名（RSU Token）
                        rsu_sk, rsu_pk = ed25519_generate_keypair()
                        token_msg = f"window_{int(event['timestamp']) // 60}".encode()
                        token_sig = ed25519_sign(rsu_sk, token_msg)
                        
                        # 2. Merkle证明
                        # 使用event中的geohash，如果不在白名单中，使用第一个
                        geohash = event.get('geohash', whitelist[0] if whitelist else 'wtw3s8n')
                        if geohash not in whitelist:
                            geohash = whitelist[0] if whitelist else 'wtw3s8n'
                        
                        merkle_root_hash = merkle_root(whitelist)
                        geohash_index = whitelist.index(geohash)
                        merkle_path = merkle_proof(whitelist, geohash_index)
                        
                        # 3. Bulletproofs范围证明
                        timestamp = int(event['timestamp'])
                        window_id = timestamp // 60
                        blinding = random.randint(1, 1000000)
                        range_proof = range_proof_prove(timestamp, window_id * 60, (window_id + 1) * 60, blinding)
                        
                        # 4. LSAG环签名
                        ring_size = 8
                        ring_keys = [ed25519_generate_keypair() for _ in range(ring_size)]
                        ring_pubkeys = [pk for _, pk in ring_keys]
                        signer_sk = ring_keys[0][0]
                        message = f"{geohash}|{timestamp}".encode()
                        lsag_sig = lrs_sign(message, ring_pubkeys, 0, signer_sk, b"context")
                        
                        # 将证明保存为JSON
                        packet = {
                            "token": {"signature": token_sig.hex(), "window_id": window_id},
                            "geohash": geohash,
                            "timestamp": timestamp,
                            "merkle_root": merkle_root_hash,
                            "merkle_proof": merkle_path,
                            "range_proof": range_proof,
                            "lsag_signature": lsag_sig
                        }
                        with open(temp_packet_file, 'w', encoding='utf-8') as f:
                            json.dump(packet, f)
                        
                    except Exception as e:
                        self._log(f"ZKP证明生成失败: {e}", "warning")
                        failure_count += 1
                        continue
                else:
                    # 朴素方案：仅生成基本数据包
                    packet = {
                        "token": event["token"],
                        "lat": event["lat"],
                        "lon": event["lon"],
                        "timestamp": event["timestamp"]
                    }
                    with open(temp_packet_file, 'w', encoding='utf-8') as f:
                        json.dump(packet, f)
                
                gen_end = time.perf_counter()
                gen_time = (gen_end - gen_start) * 1000  # 转换为毫秒
                
                # 测量验证时间
                verify_start = time.perf_counter()
                
                if use_zkp and temp_packet_file.exists():
                    # 使用真实的验证
                    try:
                        with open(temp_packet_file, 'r', encoding='utf-8') as f:
                            packet = json.load(f)
                        
                        # 验证范围证明
                        if range_proof_verify(packet['range_proof']):
                            success_count += 1
                        else:
                            failure_count += 1
                    except Exception as e:
                        self._log(f"ZKP验证失败: {e}", "warning")
                        failure_count += 1
                else:
                    # 朴素方案：简单验证
                    success_count += 1
                
                verify_end = time.perf_counter()
                verify_time = (verify_end - verify_start) * 1000
                
                # 总延迟
                total_latency = gen_time + verify_time
                latencies.append(total_latency)
                
                # 测量数据包大小
                if temp_packet_file.exists():
                    packet_size = temp_packet_file.stat().st_size
                    packet_sizes.append(packet_size)
                
                # 清理临时文件
                if temp_events_file.exists():
                    temp_events_file.unlink()
                if temp_packet_file.exists():
                    temp_packet_file.unlink()
                
            except Exception as e:
                self._log(f"处理事件{i}失败: {e}", "warning")
                failure_count += 1
                continue
        
        return {
            "latencies": latencies,
            "packet_sizes": packet_sizes,
            "success_count": success_count,
            "failure_count": failure_count
        }
    
    def measure_resource_usage(self) -> ResourceMetrics:
        """测量资源占用"""
        try:
            cpu_percent = self.process.cpu_percent(interval=0.1)
            memory_info = self.process.memory_info()
            memory_mb = memory_info.rss / (1024 * 1024)
            
            return ResourceMetrics(
                avg_cpu_percent=cpu_percent,
                max_cpu_percent=cpu_percent,
                avg_memory_mb=memory_mb,
                max_memory_mb=memory_mb
            )
        except Exception as e:
            self._log(f"资源测量失败: {e}", "warning")
            return ResourceMetrics()
    
    def run_simulation(self, scenario: Dict[str, Any], use_zkp: bool = True) -> SimulationResult:
        """
        运行完整的端到端仿真
        
        Args:
            scenario: 场景配置
            use_zkp: 是否使用零知识证明
        
        Returns:
            SimulationResult实例
        """
        self._log(f"开始端到端仿真: {scenario['name']} (ZKP: {use_zkp})")
        
        sim_start = time.time()
        
        # 1. 运行SUMO仿真生成事件
        events_file = self.run_sumo_simulation(scenario)
        
        # 2. 测量证明生成和验证性能
        perf_metrics = self.measure_proof_generation_and_verification(events_file, use_zkp)
        
        # 注意：不再测量CPU使用率，因为粒度太粗无意义
        
        sim_end = time.time()
        duration = sim_end - sim_start
        
        # 3. 计算指标
        latencies = perf_metrics["latencies"]
        packet_sizes = perf_metrics["packet_sizes"]
        success_count = perf_metrics["success_count"]
        failure_count = perf_metrics["failure_count"]
        total_packets = success_count + failure_count
        
        # 注意：不再计算吞吐量，避免误导性数据
        
        # 创建结果（移除resource_metrics）
        result = SimulationResult(
            scenario_name=scenario['name'],
            vehicle_count=scenario['vehicles'],
            total_packets=total_packets,
            latency_metrics=LatencyMetrics.from_measurements(latencies) if latencies else LatencyMetrics(),
            throughput_qps=0.0,  # 不再报告吞吐量
            resource_metrics=ResourceMetrics(),  # 空的资源指标
            communication_metrics=CommunicationMetrics.from_measurements(packet_sizes) if packet_sizes else CommunicationMetrics(),
            use_zkp=use_zkp,
            duration_seconds=duration,
            success_count=success_count,
            failure_count=failure_count
        )
        
        self.results.add(result)
        self._log(f"仿真完成: {result.get_summary()}")
        
        return result
    
    def run_all_scenarios(self, scenarios: List[Dict[str, Any]]) -> SimulationResultCollection:
        """运行所有场景"""
        self._log("=" * 60)
        self._log("开始运行所有端到端仿真场景")
        self._log("=" * 60)
        
        # 验证SUMO安装
        if not self.verify_sumo_installation():
            self._log("SUMO未正确安装，跳过仿真", "error")
            return self.results
        
        for scenario in scenarios:
            try:
                # 运行ZKP方案
                self._log(f"\n{'='*60}")
                self._log(f"场景: {scenario['name']} - ZKP方案")
                self._log(f"{'='*60}")
                self.run_simulation(scenario, use_zkp=True)
                
                # 运行朴素方案
                self._log(f"\n{'='*60}")
                self._log(f"场景: {scenario['name']} - 朴素方案")
                self._log(f"{'='*60}")
                self.run_simulation(scenario, use_zkp=False)
                
            except Exception as e:
                self._log(f"场景 {scenario['name']} 失败: {e}", "error")
                continue
        
        self._log("=" * 60)
        self._log(f"所有仿真场景完成，共 {len(self.results)} 项结果")
        self._log("=" * 60)
        
        return self.results
    
    def save_results(self, output_path: Path) -> None:
        """保存结果"""
        self.results.to_json(output_path)
        self._log(f"仿真结果已保存到: {output_path}")