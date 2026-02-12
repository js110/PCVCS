import os, sys, json, time, argparse, random
from pathlib import Path
from common.crypto_adapters import ed25519_generate_keypair, ed25519_sign
from common.crypto import geohash_encode

SUMO_HOME = os.environ.get("SUMO_HOME", None)
if not SUMO_HOME:
    raise RuntimeError('SUMO_HOME not set. On Windows: setx SUMO_HOME "D:\\sumo" and setx PYTHONPATH "%SUMO_HOME%\\tools"')
if (Path(SUMO_HOME)/"tools").exists():
    sys.path.append(str(Path(SUMO_HOME)/"tools"))
else:
    raise RuntimeError("SUMO tools not found at SUMO_HOME/tools")

import traci
from sumolib import checkBinary

def parse_rsus(rsu_str):
    pts = []
    for seg in rsu_str.split(";"):
        seg = seg.strip()
        if not seg: continue
        x,y = seg.split(",")
        pts.append((float(x), float(y)))
    return pts

def collect_vehicle_metrics():
    """收集车辆指标数据"""
    metrics = {
        "timestamp": traci.simulation.getTime(),
        "vehicle_count": len(traci.vehicle.getIDList()),
        "vehicles": []
    }
    
    # 收集每辆车的详细信息
    for veh_id in traci.vehicle.getIDList():
        try:
            # 获取车辆基本信息
            vehicle_data = {
                "id": veh_id,
                "speed": traci.vehicle.getSpeed(veh_id),
                "position": traci.vehicle.getPosition(veh_id),
                "road_id": traci.vehicle.getRoadID(veh_id),
                "lane_id": traci.vehicle.getLaneID(veh_id),
                "lane_position": traci.vehicle.getLanePosition(veh_id),
                # 排放数据
                "CO2_emission": traci.vehicle.getCO2Emission(veh_id),
                "CO_emission": traci.vehicle.getCOEmission(veh_id),
                "HC_emission": traci.vehicle.getHCEmission(veh_id),
                "PMx_emission": traci.vehicle.getPMxEmission(veh_id),
                "NOx_emission": traci.vehicle.getNOxEmission(veh_id),
                # 燃油消耗
                "fuel_consumption": traci.vehicle.getFuelConsumption(veh_id),
                # 其他有用的数据
                "acceleration": traci.vehicle.getAcceleration(veh_id),
                "distance": traci.vehicle.getDistance(veh_id),
                "angle": traci.vehicle.getAngle(veh_id)
            }
            metrics["vehicles"].append(vehicle_data)
        except Exception as e:
            # 跳过无法获取数据的车辆
            continue
    
    return metrics

def get_geo_bounds_from_net(net_file):
    """从网络文件获取地理边界"""
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(net_file)
        root = tree.getroot()
        
        # 查找边界信息
        location = root.find("location")
        if location is not None:
            boundary = location.get("boundary")
            if boundary:
                # boundary格式: "minX,minY,maxX,maxY"
                bounds = [float(x) for x in boundary.split(",")]
                return {
                    "min_lat": bounds[1],  # minY
                    "max_lat": bounds[3],  # maxY
                    "min_lon": bounds[0],  # minX
                    "max_lon": bounds[2]   # maxX
                }
    except Exception as e:
        print(f"警告: 无法从网络文件获取边界信息: {e}")
    
    # 默认返回上海区域
    return {
        "min_lat": 31.20,
        "max_lat": 31.25,
        "min_lon": 121.40,
        "max_lon": 121.50
    }

def position_to_geo(position, geo_bounds):
    """将网络坐标转换为地理坐标"""
    # 简单线性映射
    x, y = position
    lat_range = geo_bounds["max_lat"] - geo_bounds["min_lat"]
    lon_range = geo_bounds["max_lon"] - geo_bounds["min_lon"]
    
    # 假设网络坐标的范围是0-10000米
    lat = geo_bounds["min_lat"] + (y / 10000.0) * lat_range
    lon = geo_bounds["min_lon"] + (x / 10000.0) * lon_range
    
    return lat, lon

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--net", required=False, help="Path to SUMO net (.net.xml)")
    ap.add_argument("--cfg", required=False, help="Path to SUMO configuration file (.sumocfg)")
    ap.add_argument("--rsu", required=True, help='Semicolon-separated RSU xy positions in net coordinates, e.g., "100,200; 300,400"')
    ap.add_argument("--window", type=int, default=60, help="token window length (s)")
    ap.add_argument("--token-expiry", type=int, default=3600, help="token expiry time in seconds (default: 3600s = 1 hour)")
    ap.add_argument("--steps", type=int, default=300, help="simulation steps")
    ap.add_argument("--out", type=str, default=str(Path(__file__).parent.parent / "data" / "rsu_events.json"))
    ap.add_argument("--collect-metrics", action="store_true", help="Collect vehicle metrics data")
    args = ap.parse_args()

    # 检查必须提供net或cfg参数之一
    if not args.net and not args.cfg:
        ap.error("Either --net or --cfg must be provided")

    rsu_positions = parse_rsus(args.rsu)
    rsus = []
    for i in range(len(rsu_positions)):
        sk, pk = ed25519_generate_keypair()
        # 保存私钥和公钥的十六进制表示
        sk_hex = sk.hex() if isinstance(sk, bytes) else bytes(sk).hex()
        pk_hex = pk.hex() if isinstance(pk, bytes) else bytes(pk).hex()
        rsus.append({
            "rsu_id": i+1, 
            "sk_hex": sk_hex,
            "pk_hex": pk_hex
        })

    sumoBinary = checkBinary('sumo')
    # 根据提供的参数启动SUMO
    if args.cfg:
        traci.start([sumoBinary, "-c", args.cfg])
        # 从配置文件获取网络文件路径
        import xml.etree.ElementTree as ET
        cfg_tree = ET.parse(args.cfg)
        cfg_root = cfg_tree.getroot()
        net_file_elem = cfg_root.find(".//net-file")
        if net_file_elem is not None:
            net_file = Path(args.cfg).parent / net_file_elem.get("value")
        else:
            net_file = None
    else:
        traci.start([sumoBinary, "-n", args.net])
        net_file = args.net
    
    # 获取地理边界信息
    geo_bounds = get_geo_bounds_from_net(net_file) if net_file else None
    print(f"地理边界: {geo_bounds}")
    
    start_time = int(time.time())  # 使用当前时间作为起始时间
    events = []
    metrics_data = []
    
    # 加载白名单地理哈希
    whitelist_file = Path(__file__).parent.parent / "data" / "whitelist_geohash.txt"
    whitelist_geohashes = set()
    if whitelist_file.exists():
        whitelist_geohashes = set(whitelist_file.read_text().strip().split("\n"))
    
    try:
        for step in range(args.steps):
            traci.simulationStep()
            
            # 收集车辆指标数据（如果启用）
            if args.collect_metrics:
                metrics = collect_vehicle_metrics()
                metrics_data.append(metrics)
            
            if step % args.window == 0:
                window_id = step // args.window + 1
                for i, (x,y) in enumerate(rsu_positions):
                    rsu = rsus[i]
                    # 将十六进制私钥转换为bytes
                    sk_bytes = bytes.fromhex(rsu["sk_hex"])
                    nonce = random.getrandbits(64)
                    # 使用动态配置的过期时间
                    expiry = start_time + step + args.window + args.token_expiry
                    msg = f"{1}|NET|{window_id}|{nonce}|{expiry}|{rsu['rsu_id']}".encode()
                    sig = ed25519_sign(sk_bytes, msg)
                    token = {
                        "version": 1, "region_id": "NET", "window_id": window_id,
                        "nonce": nonce, "expiry_ts": expiry, "rsu_id": rsu["rsu_id"],
                        "signature_hex": sig.hex()
                    }
                    
                    # 使用地理边界信息转换坐标
                    if geo_bounds:
                        lat, lon = position_to_geo((x, y), geo_bounds)
                    else:
                        # 默认使用上海区域
                        lat = 31.23 + (y/100000.0)
                        lon = 121.47 + (x/100000.0)
                        
                    g7 = geohash_encode(lat, lon, precision=7)
                    
                    # 确保生成的地理哈希在白名单中
                    if whitelist_geohashes and g7 not in whitelist_geohashes:
                        # 如果不在白名单中，使用白名单中的第一个地理哈希
                        g7 = list(whitelist_geohashes)[0]
                    
                    events.append({"token": token, "lat": lat, "lon": lon, "geohash7": g7, "timestamp": start_time + step})
            # 更新当前时间
            # 注意：在SUMO仿真中，我们不需要手动更新时间，因为step已经代表了时间步
    finally:
        traci.close()

    output_data = {
        "rsus": rsus,
        "events": events
    }
    
    # 如果收集了指标数据，则添加到输出中
    if args.collect_metrics and metrics_data:
        output_data["metrics"] = metrics_data

    Path(args.out).write_text(json.dumps(output_data, ensure_ascii=False, indent=2))
    print(f"[OK] TraCI events saved -> {args.out}")

if __name__ == "__main__":
    main()