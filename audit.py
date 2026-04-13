#!/usr/bin/env python3
"""
AEGIS - Script d'audit automatisé
PME TechSud - Projet SSI BTC1
"""

import subprocess
import json
import socket
import datetime
import csv

def get_open_ports():
    result = subprocess.run(
        ["nmap", "-sV", "127.0.0.1"],
        capture_output=True, text=True
    )
    ports = []
    for line in result.stdout.splitlines():
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            ports.append({
                "port": parts[0],
                "state": parts[1],
                "service": parts[2] if len(parts) > 2 else "unknown",
                "version": " ".join(parts[3:]) if len(parts) > 3 else ""
            })
    return ports

def check_ssh_config():
    checks = {
        "PermitRootLogin": {"expected": "no", "found": None, "compliant": False},
        "PasswordAuthentication": {"expected": "no", "found": None, "compliant": False},
        "Port": {"expected": "2222", "found": None, "compliant": False},
        "PubkeyAuthentication": {"expected": "yes", "found": None, "compliant": False},
        "MaxAuthTries": {"expected": "3", "found": None, "compliant": False},
    }
    try:
        with open("/etc/ssh/sshd_config", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                for key in checks:
                    if line.startswith(key):
                        value = line.split()[1] if len(line.split()) > 1 else ""
                        checks[key]["found"] = value
                        checks[key]["compliant"] = (value == checks[key]["expected"])
    except PermissionError:
        print("[!] Executer avec sudo pour lire sshd_config")
    return checks

def check_firewall():
    result = subprocess.run(
        ["sudo", "ufw", "status", "verbose"],
        capture_output=True, text=True
    )
    return {
        "active": "Status: active" in result.stdout,
        "rules": result.stdout
    }

def check_fail2ban():
    result = subprocess.run(
        ["sudo", "fail2ban-client", "status", "sshd"],
        capture_output=True, text=True
    )
    banned = 0
    for line in result.stdout.splitlines():
        if "Currently banned" in line:
            banned = int(line.split(":")[-1].strip())
    return {
        "active": result.returncode == 0,
        "details": result.stdout,
        "currently_banned": banned
    }

def check_users():
    users = []
    with open("/etc/passwd", "r") as f:
        for line in f:
            parts = line.strip().split(":")
            if parts[6] in ["/bin/bash", "/bin/sh", "/bin/zsh"]:
                users.append({
                    "username": parts[0],
                    "uid": parts[2],
                    "gid": parts[3],
                    "home": parts[5],
                    "shell": parts[6]
                })
    return users

def check_listening_services():
    result = subprocess.run(
        ["ss", "-tulnp"],
        capture_output=True, text=True
    )
    return result.stdout

def generate_report():
    report = {
        "meta": {
            "date": datetime.datetime.now().isoformat(),
            "hostname": socket.gethostname(),
            "auditor": "AEGIS - Audit automatise",
            "target": "192.168.1.43"
        },
        "open_ports": get_open_ports(),
        "ssh_hardening": check_ssh_config(),
        "firewall": check_firewall(),
        "fail2ban": check_fail2ban(),
        "users": check_users(),
        "listening_services": check_listening_services()
    }

    ssh_checks = report["ssh_hardening"]
    compliant_count = sum(1 for v in ssh_checks.values() if v["compliant"])
    total_checks = len(ssh_checks)

    report["summary"] = {
        "ssh_compliance": f"{compliant_count}/{total_checks}",
        "firewall_active": report["firewall"]["active"],
        "fail2ban_active": report["fail2ban"]["active"],
        "total_open_ports": len(report["open_ports"]),
        "total_users_with_shell": len(report["users"]),
        "risk_level": "LOW" if (compliant_count == total_checks
                                and report["firewall"]["active"]
                                and report["fail2ban"]["active"]) else "MEDIUM"
    }

    return report

def export_json(report, filename="audit_report.json"):
    with open(filename, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[+] Rapport JSON exporte : {filename}")

def export_csv(report, filename="audit_ports.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["port", "state", "service", "version"])
        writer.writeheader()
        writer.writerows(report["open_ports"])
    print(f"[+] Rapport CSV ports exporte : {filename}")

if __name__ == "__main__":
    print("=" * 60)
    print("  AEGIS - Audit de securite automatise")
    print("  PME TechSud - Projet SSI")
    print("=" * 60)

    report = generate_report()

    print(f"\n[*] Date : {report['meta']['date']}")
    print(f"[*] Machine : {report['meta']['hostname']}")

    print(f"\n--- Ports ouverts ({report['summary']['total_open_ports']}) ---")
    for p in report["open_ports"]:
        print(f"  {p['port']}  {p['state']}  {p['service']}  {p['version']}")

    print(f"\n--- Conformite SSH : {report['summary']['ssh_compliance']} ---")
    for k, v in report["ssh_hardening"].items():
        status = "OK" if v["compliant"] else "FAIL"
        print(f"  [{status}] {k}: attendu={v['expected']}, trouve={v['found']}")

    print(f"\n--- Pare-feu : {'Actif' if report['summary']['firewall_active'] else 'Inactif'} ---")
    print(f"--- fail2ban : {'Actif' if report['summary']['fail2ban_active'] else 'Inactif'} ---")
    print(f"--- Niveau de risque : {report['summary']['risk_level']} ---")

    export_json(report)
    export_csv(report)

    print("\n[+] Audit termine.")
