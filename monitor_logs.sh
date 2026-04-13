#!/bin/bash
echo "=== Dernières tentatives SSH échouées ==="
sudo grep "Failed password" /var/log/auth.log | tail -20

echo ""
echo "=== IP bannies par fail2ban ==="
sudo fail2ban-client status sshd

echo ""
echo "=== Connexions actives ==="
ss -tulnp

echo ""
echo "=== Derniers logs critiques ==="
sudo journalctl -p err --since "24 hours ago" --no-pager | tail -20
