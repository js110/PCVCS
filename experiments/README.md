# 携证式群智感知系统综合实验框架

## 目录结构

```
experiments/
├── __init__.py              # 模块初始化
├── config.py                # 配置管理
├── logger.py                # 日志系统
├── example_config.json      # 示例配置文件
├── models/                  # 数据模型
│   ├── __init__.py
│   ├── benchmark_result.py
│   ├── simulation_result.py
│   ├── detection_result.py
│   └── ablation_result.py
├── modules/                 # 实验模块
│   ├── __init__.py
│   ├── crypto_benchmark.py
│   ├── end_to_end_simulator.py
│   ├── security_tester.py
│   └── ablation_experiment.py
├── visualization/           # 图表生成
│   ├── __init__.py
│   ├── chart_generator.py
│   └── report_generator.py
├── controller.py            # 实验控制器
└── README.md               # 本文件
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements_experiments.txt
```

### 2. 运行实验

```bash
# 运行完整实验套件
python run_comprehensive_experiments.py

# 运行特定模块
python run_comprehensive_experiments.py --module crypto_benchmark

# 使用自定义配置
python run_comprehensive_experiments.py --config custom_config.json

# 仅生成图表
python run_comprehensive_experiments.py --charts-only
```

### 3. 查看结果

实验结果将保存在 `experiment_results/` 目录下，包括：
- `raw_data/`: 原始实验数据（JSON格式）
- `charts/`: 生成的图表（PDF/PNG格式）
- `reports/`: 实验报告（Markdown格式）
- `experiment.log`: 详细日志

## 配置说明

配置文件使用JSON格式，主要参数包括：

- `ring_sizes`: LSAG环签名的环大小列表
- `merkle_leaf_counts`: Merkle树的叶子数量列表
- `bulletproof_batch_sizes`: Bulletproofs批量大小列表
- `simulation_scenarios`: 仿真场景配置
- `attack_sample_count`: 每种攻击的样本数量
- `benchmark_iterations`: 基准测试迭代次数
- `output_dir`: 输出目录
- `chart_format`: 图表格式（pdf/png/svg）
- `chart_dpi`: 图表分辨率
- `language`: 图表语言（en/zh）

详细配置说明请参考 `example_config.json`。

## 模块说明

### 配置管理 (config.py)
- 提供实验参数的配置和加载功能
- 支持从JSON文件加载自定义配置
- 自动验证配置参数的有效性

### 日志系统 (logger.py)
- 统一的日志记录接口
- 支持控制台和文件输出
- 多级别日志（DEBUG, INFO, WARNING, ERROR, CRITICAL）

### 数据模型 (models/)
- 定义实验结果的数据结构
- 支持JSON序列化和反序列化
- 提供统计和分析方法

### 实验模块 (modules/)
- 密码学原语基准测试
- 端到端仿真
- 安全性测试
- 消融实验

### 可视化 (visualization/)
- 生成符合IEEE期刊标准的图表
- 支持多种图表类型
- 自动生成实验报告

### 实验控制器 (controller.py)
- 编排实验流程
- 错误处理和恢复
- 断点续传支持

## 开发指南

### 添加新的实验模块

1. 在 `modules/` 目录下创建新模块
2. 实现相应的测试方法
3. 在 `controller.py` 中注册模块
4. 更新配置文件添加相关参数

### 添加新的图表类型

1. 在 `visualization/chart_generator.py` 中添加生成方法
2. 遵循IEEE期刊图表规范
3. 支持中英文双语标签

### 运行测试

```bash
pytest tests/ -v --cov=experiments
```

## 许可证

请查看项目根目录的 LICENSE 文件。
