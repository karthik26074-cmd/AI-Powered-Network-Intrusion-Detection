# 🛡️ Network Intrusion Detection System (NIDS)

<div align="center">

![NIDS Logo](https://img.shields.io/badge/NIDS-Intrusion%20Detection-red?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-green?style=for-the-badge&logo=flask)
![ML](https://img.shields.io/badge/Machine%20Learning-Sklearn-yellow?style=for-the-badge&logo=scikit-learn)

**A comprehensive Network Intrusion Detection System that leverages machine learning to identify and alert on potential security threats in real-time network traffic.**

[🚀 Getting Started](#installation) • [📖 Documentation](#usage) • [🎯 Features](#features) • [🤝 Contributing](#contributing)

</div>

---

## 🌟 Overview

This NIDS project provides an intelligent security solution that continuously monitors network traffic, analyzes patterns using advanced machine learning algorithms, and provides real-time alerts for potential intrusions. Built with Python, Flask, and Scikit-learn, it offers both a powerful backend detection engine and an intuitive web-based dashboard for security monitoring.

## 🎯 Features

<div align="center">

| Feature | Description |
|---------|-------------|
| 🕵️ **Real-time Monitoring** | Continuously monitors network traffic for suspicious patterns |
| 🤖 **ML-Powered Detection** | Uses advanced machine learning models to identify various attack types |
| 📊 **Interactive Dashboard** | Modern web-based interface for visualizing network activity |
| 🚨 **Smart Alert System** | Real-time alerts with detailed threat information |
| 📈 **Historical Analysis** | Stores and analyzes historical data for trend identification |
| 🔍 **Deep Packet Inspection** | Analyzes network packets at multiple layers |

</div>

## 🚀 Installation

### 📋 Prerequisites

- **Python 3.8+** 
- **pip** package manager
- **Administrative privileges** (for network packet capture)

### ⚙️ Quick Setup

1. **Clone the repository**
```bash
git clone https://github.com/abhiramnaik33/NIDS.git
cd NIDS
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure environment**
```bash
# Copy and configure environment variables
cp .env.example .env
# Edit .env with your specific settings
```

4. **Initialize the database**
```bash
python models.py
```

## 📖 Usage

### 🎮 Running the Application

1. **Start the NIDS service**
```bash
python app.py
```

2. **Access the dashboard**
```
http://localhost:5000
```

3. **Monitor network activity** through the intuitive web interface

### 🔧 Model Training

To train or retrain the detection model with custom data:
```bash
python inspect_model.py
```

### 📊 Dashboard Navigation

- **Home**: Real-time traffic overview and alert summary
- **Analytics**: Detailed network statistics and trends  
- **Alerts**: Comprehensive alert history and management
- **Settings**: Configuration and model management

## Project Structure

```
NIDS/
├── app.py                 # Main Flask application
├── model_service.py       # Model prediction service
├── inspect_model.py       # Model training and inspection
├── sniffer.py             # Network packet capture
├── alert_manager.py       # Alert management system
├── models.py              # Database models
├── requirements.txt       # Python dependencies
├── nids_model.pkl         # Trained machine learning model
├── .env                   # Environment variables
├── static/                # Static web assets
│   ├── css/
│   └── js/
├── templates/             # HTML templates
└── instance/              # Database files
```

## Dashboard Features

<div align="center">

| Feature | What it Does |
|---------|--------------|
| Live Traffic Monitor | Real-time visualization of network packets |
| Alert Feed | Instant notifications for detected threats |
| Analytics Panel | Comprehensive network statistics |
| Historical View | Past traffic analysis and trends |
| Threat Details | In-depth analysis of security events |

</div>

## Detection Capabilities

The system employs advanced ML algorithms to detect:

### Attack Types
- DoS Attacks (Denial of Service)
- Probe Attacks (Network reconnaissance)
- R2L Attacks (Remote to Local exploitation)
- U2R Attacks (User to Root privilege escalation)
- Malicious Patterns (Known threat signatures)
- Anomalous Behavior (Unusual traffic patterns)

### Detection Methods
- Pattern Recognition using trained classifiers
- Statistical Analysis of network behavior
- Deep Packet Inspection at multiple OSI layers
- Behavioral Analysis for zero-day threats

## Configuration

### Environment Variables

Configure the following variables in your `.env` file:

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_ENV` | Environment mode | `development` |
| `SECRET_KEY` | Flask secret key | auto-generated |
| `DATABASE_URL` | Database connection | `sqlite:///instance/nids.db` |
| `THRESHOLD` | Detection sensitivity | `0.8` |

### Model Configuration

- **Model parameters** can be adjusted in `inspect_model.py`
- **Detection thresholds** can be modified in `model_service.py`
- **Alert preferences** configurable via dashboard settings

## Contributing

<div align="center">

We welcome contributions! Here's how you can help:

</div>

### Quick Contribution Guide

1. **Fork** the repository
2. **Create** a feature branch
   ```bash
   git checkout -b feature/AmazingFeature
   ```
3. **Commit** your changes
   ```bash
   git commit -m 'Add some AmazingFeature'
   ```
4. **Push** to the branch
   ```bash
   git push origin feature/AmazingFeature
   ```
5. **Open** a Pull Request

### Contribution Areas

- **Bug Fixes**: Help us squash those bugs!
- **New Features**: Propose innovative detection methods
- **Documentation**: Improve guides and API docs
- **Testing**: Enhance test coverage
- **UI/UX**: Make the dashboard more intuitive

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## Disclaimer

<div align="center">

**Important Security Notice**

This tool is intended for **educational and research purposes only**. 

- Ensure you have **proper authorization** before monitoring any network traffic
- Use responsibly and in compliance with applicable laws and regulations
- The authors are not responsible for misuse of this software

</div>

## Contact

<div align="center">

**Abhiram Naik**

[![GitHub](https://img.shields.io/badge/GitHub-abhiramnaik33-blue?style=flat-square&logo=github)](https://github.com/abhiramnaik33)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Abhiram%20Naik-blue?style=flat-square&logo=linkedin)](https://linkedin.com/in/abhiramnaik33)

</div>

## Acknowledgments

<div align="center">

Special thanks to:

- **Python Community** for amazing libraries
- **Scikit-learn Team** for ML frameworks
- **Flask Developers** for the web framework
- **Security Researchers** for datasets and methodologies
- **Contributors** who help improve this project

</div>

---

<div align="center">

**If this project helped you, please give it a star!**

Made with  for cybersecurity enthusiasts

</div>