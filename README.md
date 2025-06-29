# 🛡️ SOC-Log-Analyzer

**Professional Security Operations Center (SOC) log analysis system with real-time threat detection and interactive dashboard.**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-SOC%20Ready-red.svg)](README.md)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange.svg)](https://attack.mitre.org/)

## 📋 Overview

SOC-Log-Analyzer is an enterprise-grade security analysis system designed for Security Operations Centers. It implements advanced threat detection algorithms, professional alert management, and provides real-time security dashboards for analysts.

### 🎯 Key Features

- **🔍 Advanced Threat Detection**: 5 sophisticated brute force detection techniques
- **🚨 Professional Alert Management**: MITRE ATT&CK mapping with auto-escalation
- **📊 Interactive SOC Dashboard**: Real-time threat visualization and metrics
- **🌍 Global Threat Intelligence**: Geographic attack mapping and IOC tracking
- **📈 Predictive Analytics**: ML-driven attack forecasting and trend analysis
- **🏗️ Scalable Architecture**: Modular design for enterprise deployment

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/[your-username]/SOC-Log-Analyzer.git
cd SOC-Log-Analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Generate sample data
python scripts/massive_log_generator.py

# Run analysis
python main.py --input data/enterprise_auth_complete.log --analyze --report

# Launch dashboard
python main.py --dashboard

# Complete security analysis
python main.py --input data/auth.log --analyze --report

# Interactive dashboard
python main.py --dashboard

# Custom detection thresholds
python main.py --input data/auth.log --analyze --threshold 5 --time-window 3



SOC-Log-Analyzer/
├── 📁 parsers/           # Specialized log parsing modules
├── 📁 detectors/         # Threat detection engines
├── 📁 alerting/          # Professional alert management
├── 📁 dashboard/         # Interactive web interface
├── 📁 scripts/           # Utility scripts and generators
└── 📁 output/            # Analysis results and reports


🚨 THREAT ANALYSIS RESULTS
===============================
✅ Events processed: 6,884
🌐 Unique IPs detected: 40
🚨 Security alerts: 43
🎯 Critical threats: 2
🌍 Countries involved: 12
⏱️ Analysis time: <1 second



# Run test suite
python -m pytest tests/ -v

# Generate test data
python scripts/massive_log_generator.py

# Validate detectors
python tests/test_detectors.py

# Run test suite
python -m pytest tests/ -v

# Generate test data
python scripts/massive_log_generator.py

# Validate detectors
python tests/test_detectors.py