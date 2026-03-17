import subprocess
import time
import random

print("[*] Simulating attack scenario...")
print("[*] Watch your dashboard at http://localhost:5000")
print()

commands = [
    'echo "2026-03-17T03:00:01.000000+05:00 abbaskhan-VMware sshd: Failed password for root from 10.10.10.5 port 22 ssh2" | sudo tee -a /var/log/auth.log',
    'echo "2026-03-17T03:00:03.000000+05:00 abbaskhan-VMware sshd: Failed password for root from 10.10.10.5 port 22 ssh2" | sudo tee -a /var/log/auth.log',
    'echo "2026-03-17T03:00:05.000000+05:00 abbaskhan-VMware sshd: Failed password for root from 10.10.10.5 port 22 ssh2" | sudo tee -a /var/log/auth.log',
    'echo "2026-03-17T03:00:07.000000+05:00 abbaskhan-VMware sshd: Failed password for root from 10.10.10.5 port 22 ssh2" | sudo tee -a /var/log/auth.log',
    'echo "2026-03-17T03:00:09.000000+05:00 abbaskhan-VMware sshd: Failed password for root from 10.10.10.5 port 22 ssh2" | sudo tee -a /var/log/auth.log',
    'echo "2026-03-17T03:15:00.000000+05:00 abbaskhan-VMware sshd: Accepted password for admin from 203.0.113.42 port 44321 ssh2" | sudo tee -a /var/log/auth.log',
    'echo "2026-03-17T03:16:00.000000+05:00 abbaskhan-VMware sudo: admin : TTY=pts/0 ; COMMAND=/bin/bash" | sudo tee -a /var/log/auth.log',
    'echo "2026-03-17T03:17:00.000000+05:00 abbaskhan-VMware useradd: new user: name=backdoor, UID=1001, GID=1001" | sudo tee -a /var/log/auth.log',
    'echo "2026-03-17T03:18:00.000000+05:00 abbaskhan-VMware sudo: admin : TTY=pts/0 ; COMMAND=/usr/sbin/usermod -aG sudo backdoor" | sudo tee -a /var/log/auth.log',
    'echo "2026-03-17T03:19:00.000000+05:00 abbaskhan-VMware sshd: Invalid user ghost from 10.10.10.99 port 22" | sudo tee -a /var/log/auth.log',
]

for i, cmd in enumerate(commands, 1):
    print(f"[{i}/{len(commands)}] Injecting attack event...")
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL)
    time.sleep(1)

print()
print("[*] Attack simulation complete!")
print("[*] Check your dashboard — alerts should be firing")