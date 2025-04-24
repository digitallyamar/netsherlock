# NetSherlock

A Python-based network scanner to discover devices, open ports, and operating systems on a specified subnet. Outputs results to a CSV file.

## Features
- Scans subnets using `nmap` for host discovery, port scanning, and OS detection.
- Supports multiple platforms: Linux, Windows Server, and cloud (AWS, Azure, GCP).
- Customizable port lists via command-line arguments.
- Saves results to a CSV file with IP, device name, OS, and open ports.

## Requirements
- Python 3.6+
- `nmap` (command-line tool)
- `python-nmap` (Python library)

## Installation
```bash
# Install dependencies (Linux)
sudo apt update
sudo apt install python3 python3-pip nmap
pip install python-nmap

# Create virtual environment
python3 -m venv netsherlock-venv
source netsherlock-venv/bin/activate

# Usage
    `
        sudo netsherlock-venv/bin/python3 sherlock.py --subnets 192.168.1.0/24 --output results.csv --ports 22,80,443
    `