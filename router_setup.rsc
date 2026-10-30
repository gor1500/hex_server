# hEX Command Center - Router Setup Script
# Paste this into the MikroTik terminal (SSH or WinBox)

# 1. Enable REST API (Required for Dashboard)
/ip service enable www-ssl
/ip service set www-ssl port=443 certificate=none

# 2. Basic Firewall Protection
/ip firewall filter add chain=input action=drop in-interface=pppoe-wan comment="Drop WAN to Router"
/ip firewall filter add chain=forward action=drop connection-state=invalid comment="Drop Invalid Packets"

# 3. Brute Force Protection
/ip firewall filter add chain=input protocol=tcp dst-port=22,8291 src-address-list=ssh_blacklist action=drop comment="Drop Blacklisted"
/ip firewall filter add chain=input protocol=tcp dst-port=22,8291 src-address-list=ssh_stage3 action=add-src-to-address-list address-list=ssh_blacklist address-list-timeout=1d comment="Stage 3"
/ip firewall filter add chain=input protocol=tcp dst-port=22,8291 src-address-list=ssh_stage2 action=add-src-to-address-list address-list=ssh_stage3 address-list-timeout=1m comment="Stage 2"
/ip firewall filter add chain=input protocol=tcp dst-port=22,8291 src-address-list=ssh_stage1 action=add-src-to-address-list address-list=ssh_stage2 address-list-timeout=1m comment="Stage 1"
/ip firewall filter add chain=input protocol=tcp dst-port=22,8291 src-address-list=!ssh_stage1 action=add-src-to-address-list address-list=ssh_stage1 address-list-timeout=1m comment="Stage 0"

# 4. Honeypot (Port 22 redirect)
/ip firewall nat add chain=dstnat protocol=tcp dst-port=22 in-interface=pppoe-wan action=dst-nat to-addresses=192.168.88.99 to-ports=22 comment="Honeypot SSH"
/ip firewall filter add chain=forward dst-address=192.168.88.99 action=log log-prefix="HONEYPOT-ALERT" comment="Log Honeypot"
/ip firewall filter add chain=forward dst-address=192.168.88.99 action=drop comment="Drop Honeypot"

# 5. Netwatch (Auto-Recovery)
/tool netwatch add host=1.1.1.1 interval=1m timeout=3s \
    down-script="/log info \"NETWATCH: Internet DOWN\"; /interface/pppoe-client disable [find name=\"pppoe-wan\"]; :delay 5s; /interface/pppoe-client enable [find name=\"pppoe-wan\"]" \
    up-script="/log info \"NETWATCH: Internet UP\""

# 6. Local DNS for Dashboard
/ip dns static add name=dashboard.lan address=192.168.88.50
/ip dns static add name=router.lan address=192.168.88.1

# 7. Bedtime Rule Placeholder
/ip firewall filter add chain=forward src-address=192.168.88.0/24 action=drop time=22:00:00-06:00:00,mon,tue,wed,thu,fri,sat,sun disabled=yes comment="Bedtime for Wi-Fi"

:log info "hEX Command Center Router Setup Complete"
