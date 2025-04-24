import nmap
import csv
import datetime
import argparse
import platform
import os
import sys
import logging
import shutil

# Set up logging for debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_dependencies():
    """Check if nmap and python-nmap are installed and accessible."""
    try:
        # Verify python-nmap is importable
        import nmap
        logger.info(f"python-nmap version: {nmap.__version__}")
    except ImportError:
        logger.error("python-nmap is not installed. Install with 'pip install python-nmap'.")
        return False

    # Verify nmap binary is installed
    nmap_binary = shutil.which('nmap')
    if not nmap_binary:
        logger.error("nmap binary not found. Install with 'sudo apt install nmap' (Linux) or download from https://nmap.org (Windows).")
        return False
    logger.info(f"nmap binary found at: {nmap_binary}")

    return True

def scan_subnet(subnet, nm, ports="22,53,80,443,135,1935,2179,3240,8090,57340"):
    """Scan a single subnet and return device information."""
    logger.info(f"Scanning subnet: {subnet}")
    scan_args = f'-sT -O -p {ports} --osscan-guess --osscan-limit'
    
    # Windows requires admin privileges; Linux requires sudo
    if platform.system() == "Windows" and not is_admin():
        logger.warning("Admin privileges required for nmap on Windows. Please run as administrator.")
        return []
    
    try:
        nm.scan(hosts=subnet, arguments=scan_args)
    except nmap.PortScannerError as e:
        logger.error(f"Error scanning {subnet}: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error during scan: {e}")
        return []

    devices = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            ip = host
            hostname = nm[host].hostname() or 'Unknown'
            os_info = 'Unknown'
            ports = []

            # Get OS information
            if 'osclass' in nm[host]:
                os_info = ', '.join(f"{os['osfamily']} {os['osgen']}" for os in nm[host]['osclass'])
            elif 'osmatch' in nm[host]:
                os_info = ', '.join(os['name'] for os in nm[host]['osmatch'])

            # Get open ports
            for proto in nm[host].all_protocols():
                if proto in nm[host]:
                    ports.extend(
                        f"{port}/{proto}" for port in nm[host][proto].keys()
                        if nm[host][proto][port]['state'] == 'open'
                    )

            devices.append({
                'IP Address': ip,
                'Device Name': hostname,
                'Operating System': os_info,
                'Ports': ', '.join(ports) if ports else 'None'
            })

    return devices

def save_to_csv(devices, output_file):
    """Save device information to a CSV file."""
    try:
        # If output_file is relative, use current working directory
        if not os.path.isabs(output_file):
            output_file = os.path.join(os.getcwd(), output_file)
        
        # Ensure output directory exists
        output_dir = os.path.dirname(output_file)
        if output_dir:  # Only create directory if there is one
            os.makedirs(output_dir, exist_ok=True)
        
        logger.info(f"Saving results to: {output_file}")
        headers = ['IP Address', 'Device Name', 'Operating System', 'Ports']
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for device in devices:
                writer.writerow(device)
        logger.info(f"Results saved to {output_file}")
    except Exception as e:
        logger.error(f"Error saving CSV: {e}")

def is_admin():
    """Check if the script is running with admin/root privileges."""
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        return os.geteuid() == 0

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Network scanner for multiple subnets")
    parser.add_argument(
        '--subnets', nargs='+', required=True,
        help="Subnets to scan (e.g., 192.168.104.0/24)"
    )
    parser.add_argument(
        '--output', default=f"scan_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        help="Output CSV file name"
    )
    parser.add_argument(
        '--ports', default="22,53,80,443,135,1935,2179,3240,8090,57340",
        help="Ports to scan (e.g., 22,80,443)"
    )
    args = parser.parse_args()

    # Check dependencies
    if not check_dependencies():
        logger.error("Please install nmap and python-nmap. Exiting.")
        sys.exit(1)

    # Initialize nmap scanner
    nm = nmap.PortScanner()

    # Check privileges
    if not is_admin():
        logger.error("This script requires root/admin privileges for nmap scans.")
        sys.exit(1)

    # Scan all subnets and collect results
    all_devices = []
    for subnet in args.subnets:
        devices = scan_subnet(subnet, nm, args.ports)
        all_devices.extend(devices)

    # Save results to CSV
    if all_devices:
        save_to_csv(all_devices, args.output)
    else:
        logger.warning("No devices found.")

if __name__ == "__main__":
    main()