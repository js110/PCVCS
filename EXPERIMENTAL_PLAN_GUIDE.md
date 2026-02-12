# 实验方案执行指南

## 概述

本文档说明如何执行基于设计文档的完整实验方案。实验方案包含4大阶段实验，产出6个复合图表（约20个子图）。

**最新更新（2025-11-29）**：
- ✅ 所有图表已中文化
- ✅ 图表1已优化为更直观的版本
- ✅ 图表4已简化为只保留折线图

## 设计文档

设计文档位于：`.qoder/quests/experimental-plan-design.md`

包含以下内容：
- 实验目标和架构
- 5大类实验的详细设计
  - 类别1：功能与安全性验证
  - 类别2：隐私保护强度评估
  - 类别3：性能与开销测量
  - 类别4：消融与对比分析
  - 类别5：实用性验证
- 7个复合图表规格
- 实验执行计划
- 质量保证机制

## 快速开始

### 1. 配置实验参数

编辑 `experimental_plan_config.json` 文件以调整实验参数：

```json
{
  "experiment_1a_functional_verification": {
    "enabled": true,
    "vehicle_counts": [20, 50, 100, 200],
    "reports_per_scenario": 1000
  },
  ...
}
```

### 2. 运行实验

```bash
# Windows PowerShell
python run_experimental_plan.py

# 或使用Python解释器
python -u run_experimental_plan.py
```

### 3. 查看结果

实验结果将保存在 `experiment_results/{timestamp}/` 目录下：

```
experiment_results/2025-11-29_12-00-00/
├── config_snapshot.json       # 配置快照
├── raw_data/                  # 原始实验数据
│   ├── experiment_1a.json
│   ├── experiment_1b.json
│   └── experiment_3a_crypto_benchmark.json
├── charts/                    # 生成的图表
│   ├── fig1_crypto_primitives.pdf
│   └── fig1_crypto_primitives.png
├── reports/                   # 实验报告
│   ├── execution.log
│   └── experiment_report.md
└── experiment_summary.json    # 执行摘要
```

## 实验模块说明

### 已实现的实验

**阶段1：环境准备与基础测试**

**实验3A：密码学原语微基准测试**
- Ed25519签名/验证性能
- Merkle树生成、证明生成、证明验证（测试8/16/32/64个叶子）
- Bulletproofs范围证明（批量大小1/10）
- LSAG环签名（环大小4/8/16/32）

**阶段2：功能与安全性验证**

**实验1A：合规报告接受率测试**
- 测试不同车辆数量下的报告接受率
- 验证功能正确性
- 检查点：接受率应≥95%

**实验1B：政击阻断率测试**
- 测试5种攻击类型的检测率
- 攻击类型：位置伪造、时间伪造、Token篡改、重放、双重上报
- 评估TPR（真阳性率）和FPR（假阳性率）

**阶段3：隐私保护强度评估**

**实验2A：位置隐私测试**
- 测试不同任务区域大小下的位置推断成功率
- 对比ZKP-LRS、BPDV、明文方案

**实验2B：时间隐私测试**
- 测试不同时间窗口下的时间推断误差
- 对比明文、粗粒度、ZKP-LRS方案

**实验2C：跨任务关联性测试**
- 测试跨任务聚类准确率
- 评估不同聚类算法的效果

**阶段4：性能与开销测量**

**实验3B：端到端延迟测试**
- 测试不同并发车辆数下的延迟
- 记录平均延迟和P95延迟

**实验3C：通信开销测试**
- 测试不同配置下的报告大小
- 变量：Merkle叶子数、环大小
- 计算不同场景下的带宽占用

**阶段5：消融与对比实验**

**实验4A：消融实验**
- 测试不同组合：明文、只有ZK、只有LRS、ZK+LRS、ZK+LRS+PQ
- 评估各组件对性能和隐私的贡献

**实验4B：基线方案对比**
- 对比BPDV、PPRM、本文方案
- 评估生成时间、验证时间、报告大小、隐私分数

## 图表生成

系统会自动生成以下IEEE论文标准图表（**所有图表均为中文版本**）：

### 已实现的图表

#### 图表1：功能与安全性验证（2×2复合图）
**状态**：✅ 已实现并优化（2025-11-29）

**子图A：政击检测率对比**
- 对比ZKP-LRS（本文）、BPDV、明文方案
- 5种政击类型：位置伪造、时间伪造、Token滥用、重放、双重报告
- 柱状图，直观展示方案优势

**子图B：三个方案的性能对比**
- 对比生成时间和验证时间
- 使用对数坐标，清晰展示数量级差异
- 数据：ZKP-LRS(11.6/2.9ms) vs BPDV(105/45ms) vs 明文(0.5/0.2ms)

**子图C：三个方案的报告大小**
- 对比报告大小：ZKP-LRS(4220) vs BPDV(3200) vs 明文(512) bytes
- 柱子上标注具体数值，非常直观

**子图D：三个方案的隐私分数对比**
- 雷达图展示四个维度：位置隐私、时间隐私、身份匿名、抗量子安全
- ZKP-LRS全满分(10/10)，BPDV部分优势，明文方案无隐私
- 直观展示综合优势

**优化说明**：
- 移除了复杂的ROC曲线对比（太专业）
- 移除了组件安全贡献堆叠图（不直观）
- 所有子图均为易于理解的对比图

---

#### 图表2：隐私保护强度评估（2×2复合图）
**状态**：✅ 已实现并中文化
- 子图A：位置推断成功率vs任务区域大小
- 子图B：时间推断误差vs窗口长度
- 子图C：跨任务聚类准确率
- 子图D：隐私增益对比

---

#### 图表3：密码学原语性能（1×3复合图）
**状态**：✅ 已实现并中文化
- 子图A：Merkle树性能与可扩展性
- 子图B：Bulletproofs性能
- 子图C：LSAG环签名性能

---

#### 图表4：端到端性能与通信开销（1×2复合图）
**状态**：✅ 已实现并简化（2025-11-29）
- 子图A：端到端延迟vs并发车辆数（折线图）
- 子图B：报告大小vs环大小（不同Merkle大小，折线图）

**优化说明**：
- 从2×2布局简化为1×2布局
- 移除了柱状图、箱线图、饼图、热力图
- 只保留最直观的折线图

---

#### 图表5：消融实验（1×2复合图）
**状态**：✅ 已实现并中文化
- 子图A：性能开销分解
- 子图B：隐私-性能权衡

---

#### 图表6：基线方案对比（1×2复合图）
**状态**：✅ 已实现并中文化
- 子图A：综合性能对比
- 子图B：综合隐私对比

---

### 图表规范

- **格式**：PDF + PNG（双格式输出）
- **分辨率**：300 DPI
- **尺寸**：
  - 双栏宽度：7.16英寸
  - 单栏宽度：3.5英寸
- **样式**：IEEE论文标准
- **语言**：✨ **全中文** （标题、标签、图例等所有文字）

## 配置参数说明

### 实验控制

```json
"experiment_1a_functional_verification": {
  "enabled": true,              // 是否启用此实验
  "vehicle_counts": [20, 50],   // 测试的车辆数量
  "reports_per_scenario": 1000  // 每个场景生成的报告数
}
```

### 输出配置

```json
"output_config": {
  "base_dir": "./experiment_results",  // 输出基础目录
  "chart_format": "pdf",               // 图表格式（pdf/png）
  "chart_dpi": 300,                    // 图表分辨率
  "include_png": true                  // 同时生成PNG版本
}
```

### 质量保证

```json
"quality_assurance": {
  "checkpoint_1_min_acceptance_rate": 0.95,  // 检查点1：最低接受率
  "checkpoint_2_max_latency_ms": 1000,       // 检查点2：最大延迟
  "random_seed": 42,                         // 随机种子
  "parallel_execution": false                // 是否并行执行
}
```

## 扩展实验

要添加新的实验模块：

1. 在 `experiments/modules/` 创建新模块
2. 实现实验逻辑并保存结果为JSON
3. 在 `experimental_plan_config.json` 添加配置
4. 在 `run_experimental_plan.py` 添加执行函数
5. 在 `chart_generator.py` 添加对应的图表生成方法

## 故障排除

### 常见问题

**Q: 实验运行缓慢怎么办？**
A: 在配置文件中减少迭代次数或样本数量，例如：
```json
"reports_per_scenario": 100  // 从1000减少到100
```

**Q: SUMO相关实验失败？**
A: 确保SUMO已正确安装并配置环境变量：
```json
"sumo_config": {
  "sumo_home": "D:/sumo"  // 修改为实际SUMO安装路径
}
```

**Q: 密码学库性能不足？**
A: 减少测试的参数范围：
```json
"merkle_leaf_counts": [8, 16, 32]  // 只测试小规模
```

### 检查点失败

如果检查点失败（例如接受率<95%），脚本会记录警告但继续执行。查看日志文件：

```
experiment_results/{timestamp}/reports/execution.log
```

## 性能优化建议

1. **并行执行**：对于独立的实验，可以启用并行执行（需谨慎测试）
2. **采样方法**：对于大规模实验，使用采样而非全量测试
3. **缓存结果**：避免重复运行相同的实验
4. **增量运行**：只运行需要的实验模块

## 数据分析

所有原始数据以JSON格式保存，便于后续分析：

```python
import json

# 加载实验数据
with open('experiment_results/{timestamp}/raw_data/experiment_1a.json') as f:
    data = json.load(f)

# 分析接受率
print(data['overall_acceptance_rate'])
```

## 引用设计文档

执行实验时请参考完整的设计文档：
- 文档路径：`.qoder/quests/experimental-plan-design.md`
- 包含详细的实验设计、评估指标、预期结果等信息

## 联系与支持

如有问题，请查看：
1. 执行日志：`reports/execution.log`
2. 错误摘要：`experiment_summary.json`中的`errors`字段
3. 设计文档：`.qoder/quests/experimental-plan-design.md`

## 版本信息

- **配置版本**：1.0
- **实验框架**：基于 `experiments/` 模块
- **图表标准**：IEEE论文规范
- **图表语言**：✨ **中文** （更新于2025-11-29）
- **日志语言**：中文

---

## 更新日志

### 2025-11-29
- ✅ 所有图表已全面中文化
- ✅ 图表1重新设计：移除ROC曲线和组件贡献图，增加性能对比、报告大小对比、隐私分数雷达图
- ✅ 图表4简化：从2×2布局改为1×2，只保留折线图
- ✅ 所有实验模块已实现并测试通过
