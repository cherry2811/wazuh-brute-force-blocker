# Wazuh Brute-Force Blocker

A Python-based SOAR (Security Orchestration, Automation, and Response) script that:
- Parses Wazuh-monitored auth logs
- Detects brute-force login attempts
- Automatically blocks attacker IPs using iptables

## How it works
- Monitors `/var/log/auth.log` for "Failed password" attempts
- Tracks attempts by IP address
- Blocks IPs with more than 5 failed logins

## Requirements
- Python 3
- Wazuh agent installed
- Root access for iptables rules

## Run
```bash
sudo python3 wazuh_brute_force_blocker.py
