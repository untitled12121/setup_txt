#!/bin/bash

# ==============================================================================
# CMPN202 - Automated Infrastructure Deployment Script (Smart Edition)
# Covers Weeks 1-7: Users, Security, Monitoring, and Auditing
# Features: Idempotent configuration, Conflict resolution, Error skipping
# Author: Anuj Baral
# ==============================================================================

LOG_FILE="/var/log/cmpn202_deploy.log"
DEBIAN_FRONTEND=noninteractive

log_info() {
    echo -e "\e[32m[INFO]\e[0m $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "\e[33m[WARN]\e[0m $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "\e[31m[ERROR]\e[0m $1" | tee -a "$LOG_FILE"
}

update_config() {
    local file="$1"
    local key="$2"
    local value="$3"

    if [ ! -f "$file" ]; then
        log_warn "File $file not found. Creating it."
        touch "$file"
    fi

    if grep -E -q "^[#\s]*$key\s+" "$file"; then
        sed -i -E "s/^[#\s]*$key\s+.*/$key $value/" "$file"
        log_info "Updated $key to $value in $file"
    else
        echo "$key $value" >> "$file"
        log_info "Appended $key $value to $file"
    fi
}

update_ini_key() {
    local file="$1"
    local section="$2"
    local key="$3"
    local value="$4"

    if grep -q "^\[$section\]" "$file"; then
        if sed -n "/^\[$section\]/,/^\[/p" "$file" | grep -q "^[#\s]*$key\s*="; then
            sed -i "/^\[$section\]/,/^\[/ s/^[#\s]*$key\s*=.*/$key = $value/" "$file"
            log_info "Updated [$section] $key = $value in $file"
        else
            sed -i "/^\[$section\]/a $key = $value" "$file"
            log_info "Added $key = $value to [$section] in $file"
        fi
    else
        log_warn "Section [$section] not found in $file. Cannot update $key."
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root."
        exit 1
    fi
}

init_system() {
    log_info "PHASE 1: Updating System Repositories..."
    {
        apt-get update -y && apt-get upgrade -y
    } || log_error "System update encountered errors."
    
    log_info "Installing core dependencies..."
    apt-get install -y openssh-server curl wget gnupg2 lsb-release || log_error "Failed to install core tools"
}

setup_users() {
    log_info "PHASE 2: Checking Identity Architecture..."

    if id "anuj" &>/dev/null; then
        log_info "User 'anuj' already exists. Skipping creation."
    else
        useradd -m -s /bin/bash anuj
        echo "anuj:TemporaryPass123!" | chpasswd
        log_info "Created user 'anuj'."
    fi

    if id "sysadmin" &>/dev/null; then
        log_info "User 'sysadmin' already exists. Skipping creation."
    else
        useradd -m -s /bin/bash sysadmin
        echo "sysadmin:SecureAdminPass123!" | chpasswd
        usermod -aG sudo sysadmin
        log_info "Created user 'sysadmin'."
    fi
}

install_tools() {
    log_info "PHASE 3: Installing Toolchain..."
    
    TOOLS="stress-ng fio btop apparmor-utils fail2ban postfix mailutils libsasl2-modules lynis nmap auditd audispd-plugins rkhunter acct"
    
    for tool in $TOOLS; do
        if dpkg -l | grep -q "^ii  $tool"; then
            log_info "$tool is already installed."
        else
            log_info "Installing $tool..."
            apt-get install -y "$tool" || log_error "Failed to install $tool. Skipping."
        fi
    done

    log_info "Updating Rootkit Hunter database..."
    rkhunter --propupd >/dev/null 2>&1 || log_warn "RKHunter update returned non-zero exit code."
}

setup_firewall() {
    log_info "PHASE 4: Configuring UFW Firewall..."
    
    if ufw status | grep -q "Status: active"; then
        log_info "UFW is already active. verifying rules..."
    else
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow 22/tcp 
        echo "y" | ufw enable
        log_info "Firewall enabled with Default Deny policy."
    fi
}

configure_fail2ban() {
    log_info "PHASE 5: Configuring Fail2Ban..."
    local jail_file="/etc/fail2ban/jail.local"

    if [ ! -f "$jail_file" ]; then
        log_info "$jail_file not found. Creating new."
        cat <<EOF > "$jail_file"

[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1h
findtime = 10m
EOF
    else
        if grep -q "^\[sshd\]" "$jail_file"; then
            log_info "[sshd] section found in $jail_file. Updating values..."
            update_ini_key "$jail_file" "sshd" "enabled" "true"
            update_ini_key "$jail_file" "sshd" "port" "ssh"
            update_ini_key "$jail_file" "sshd" "filter" "sshd"
            update_ini_key "$jail_file" "sshd" "logpath" "/var/log/auth.log"
            update_ini_key "$jail_file" "sshd" "maxretry" "3"
            update_ini_key "$jail_file" "sshd" "bantime" "1h"
        else
            log_info "[sshd] section missing. Appending to $jail_file."
            cat <<EOF >> "$jail_file"

[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1h
findtime = 10m
EOF
        fi
    fi

    systemctl restart fail2ban || log_error "Failed to restart Fail2Ban"
    systemctl enable fail2ban
}

setup_monitoring() {
    log_info "PHASE 6: Deploying Custom Monitoring Service (Overwriting)..."

    cat <<'EOF' > /usr/local/bin/week5-monitor.sh
#!/bin/bash
# Week 5 Monitoring Script
LOG_FILE="/var/log/system_monitor.csv"
CPU_THRESHOLD=80.0

if [ ! -f "$LOG_FILE" ]; then
    echo "Timestamp,CPU_Load,RAM_Usage" > "$LOG_FILE"
fi

while true; do
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    CPU_LOAD=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    RAM_USAGE=$(free -m | awk 'NR==2{printf "%.2f", $3*100/$2 }')

    echo "$TIMESTAMP,$CPU_LOAD,$RAM_USAGE" >> "$LOG_FILE"

    IS_HIGH=$(echo "$CPU_LOAD > $CPU_THRESHOLD" | bc -l 2>/dev/null)
    if [ "$IS_HIGH" -eq 1 ]; then
        echo "High Load Detected: $CPU_LOAD%" | logger -t week5-monitor
    fi

    sleep 5
done
EOF

    chmod +x /usr/local/bin/week5-monitor.sh

    cat <<EOF > /etc/systemd/system/week5-monitor.service
[Unit]
Description=Week 5 Advanced Resource Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/week5-monitor.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable week5-monitor.service
    systemctl start week5-monitor.service || log_error "Failed to start monitoring service"
    log_info "Monitoring service deployed."
}

harden_system() {
    log_info "PHASE 7: Applying Final Hardening Measures..."

    if [ -f /var/log/auth.log ]; then
        if lsattr /var/log/auth.log | grep -q "a"; then
            log_info "auth.log is already immutable."
        else
            chattr +a /var/log/auth.log
            log_info "Applied immutable (+a) attribute to auth.log."
        fi
    fi

    if grep -q "TMOUT=300" /etc/profile; then
        log_info "Shell timeout already configured in /etc/profile."
    else
        echo "readonly TMOUT=300" >> /etc/profile
        echo "export TMOUT" >> /etc/profile
        log_info "Enforced global shell timeout (300s)."
    fi

    if grep -q "UMASK.*022" /etc/login.defs; then
        sed -i 's/UMASK.*022/UMASK 027/g' /etc/login.defs
        log_info "Hardened default UMASK to 027."
    else
        log_info "UMASK already hardened or not found in standard format."
    fi

    systemctl enable auditd --now || log_error "Failed to start auditd"

    log_info "Hardening SSH Configuration..."
    local ssh_conf="/etc/ssh/sshd_config"


    cp "$ssh_conf" "${ssh_conf}.bak"

    update_config "$ssh_conf" "PermitRootLogin" "no"
    update_config "$ssh_conf" "PasswordAuthentication" "no"
    update_config "$ssh_conf" "PubkeyAuthentication" "yes"
    update_config "$ssh_conf" "LogLevel" "VERBOSE"
    update_config "$ssh_conf" "ClientAliveInterval" "300"
    update_config "$ssh_conf" "ClientAliveCountMax" "0"
    update_config "$ssh_conf" "AllowTcpForwarding" "no"
    update_config "$ssh_conf" "AllowAgentForwarding" "no"
    update_config "$ssh_conf" "PermitTunnel" "no"
    update_config "$ssh_conf" "X11Forwarding" "no"
    update_config "$ssh_conf" "MaxAuthTries" "3"
    update_config "$ssh_conf" "MaxSessions" "2"
    update_config "$ssh_conf" "TCPKeepAlive" "no"

    log_info "SSH Configuration updated. Restarting service..."
    systemctl restart ssh || log_error "Failed to restart SSH service. Check config syntax."
}

main() {
    echo "========================================================"
    echo "   CMPN202 Infrastructure Deployment (Smart Mode)"
    echo "========================================================"
    
    check_root
    init_system
    setup_users
    install_tools
    setup_firewall
    configure_fail2ban
    setup_monitoring
    harden_system
    
    echo "========================================================"
    echo "DEPLOYMENT COMPLETE"
    echo "Logs available at: $LOG_FILE"
    echo "--------------------------------------------------------"
    echo "SSH Password Authentication is DISABLED."
    echo "Ensure you have SSH keys set up before disconnecting."
    echo "========================================================"
}

main
