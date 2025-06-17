import json
import sys
import subprocess
import logging

# Setup logging
logging.basicConfig(
    filename='/home/charan/wazuh-brute-force-blocker/blocker.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def block_ip(ip):
    try:
        # Run iptables command to block IP
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        logging.info(f"Blocked IP: {ip}")
        print(f"[!] Blocking IP: {ip}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block IP {ip}: {e}")
        print(f"[!] Error blocking IP {ip}")

def main(alerts_file):
    failed_attempts = {}

    try:
        with open(alerts_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    logging.warning("Skipping invalid JSON line")
                    continue

                rule = alert.get('rule', {})
                rule_id = rule.get('id', rule.get('id'))  # Adjust if needed
                src_ip = alert.get('srcip')

                logging.debug(f"Processing alert: rule id = {rule_id}, src_ip = {src_ip}")

                if not src_ip:
                    continue

                # Check for brute force or failed login rule ids (example: 5716)
                if rule_id == 5716:
                    failed_attempts[src_ip] = failed_attempts.get(src_ip, 0) + 1

                    if failed_attempts[src_ip] >= 5:  # threshold
                        block_ip(src_ip)

    except FileNotFoundError:
        logging.error(f"Alerts file not found: {alerts_file}")
        print(f"[!] Alerts file not found: {alerts_file}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        print(f"[!] Unexpected error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 wazuh_brute_force_blocker.py /path/to/alerts.json")
        sys.exit(1)

    alerts_path = sys.argv[1]
    main(alerts_path)
