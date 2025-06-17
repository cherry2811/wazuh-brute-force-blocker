#!/usr/bin/env python3

import re
import subprocess
from collections import defaultdict

# Log file path
log_file = "/var/log/auth.log"

# Failed login regex (IPv4)
failed_login_regex = r"Failed password for .* from (\d+\.\d+\.\d+\.\d+) port"

# Threshold for brute-force
threshold = 3

# Store IPs and failed count
ip_attempts = defaultdict(int)

# Read and parse the log
with open(log_file, 'r', errors='ignore') as f:
    for line in f:
        match = re.search(failed_login_regex, line)
        if match:
            ip = match.group(1)
            ip_attempts[ip] += 1

# Block IPs that exceed threshold
for ip, count in ip_attempts.items():
    if count >= threshold:
        print(f"[!] Blocking IP: {ip} - Failed attempts: {count}")
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] Error blocking IP {ip}: {e}")
