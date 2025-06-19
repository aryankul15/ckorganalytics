# CKORGANALYTICS

**Empowering Cloud Growth Through Smarter Resource Management**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

> Built with ❤️ using Python, Boto3, and AWS

---

## Table of Contents

- [Overview](#overview)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Connect](#connect)

---

## Overview

**ckorganalytics** is a developer tool crafted to enhance AWS account oversight by automating quota assessments and resource monitoring across organizational boundaries. It simplifies the process of tracking account limits, permissions, and configurations, enabling proactive management and compliance.

### 🔍 Why ckorganalytics?

This project helps teams maintain control over their cloud environment with features including:

- ✅ **Quota Monitoring**: Retrieve specific AWS quota information to ensure resource limits are respected.
- 🔄 **Cross-Account Analysis**: Automate account assessments by assuming roles across multiple accounts for comprehensive insights.
- 📊 **Exportable Reports**: Generate CSV summaries for easy analysis and planning.
- 🔐 **Role Management**: Define and manage account configurations to enforce consistent permissions.
- ⚙️ **Automation Ready**: Streamline routine checks and reporting to improve operational efficiency.

---

## Getting Started

### Prerequisites

This project requires the following dependencies:

- **Programming Language**: Python 3.10+
- **AWS CLI**: Configured with appropriate credentials and roles
- **Pip**: Python package manager

---

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/aryankul15/ckorganalytics
2. **Navigate to project directory**
   ```bash
   cd ckorganalytics
3. **Install the dependencies**
     ```bash
     pip install -r requirements.txt

### Usage


1. **Make changes in accounts.json as per your objective**
2. **Run for analyzing the quota limit of your AWS Accounts Organizations**
   ```bash
   python analysis.py
3. **To increase the quota, Use increase-quotas.py**
   ```bash
   python increase-quotas.py

### Connect
Feel free to contribute, raise issues, or fork the repo.

Made with ❤️ by Aryan Kulshrestha
