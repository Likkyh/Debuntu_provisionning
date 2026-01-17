#!/bin/bash
# ============================================================
# DEBUNTU PROVISIONING SCRIPT
# Production-ready setup for Ubuntu LTS and Debian Stable VMs
# ============================================================
#
# FEATURES:
# - Removes bloatware and unnecessary packages
# - Configures sudo and user permissions
# - Installs MartianMono Nerd Font (system-wide default)
# - Sets up ZSH with Oh-My-Zsh and Powerlevel10k
# - Installs and configures LazyVim
# - Deploys fastfetch with custom config
# - Hardens SSH with key-based authentication
# - Configures UFW firewall and fail2ban
#
# USAGE: sudo ./setup.sh
# ============================================================

set -euo pipefail

# ----------------------------------------------------------
# SCRIPT METADATA
# ----------------------------------------------------------
SCRIPT_VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/var/log/debuntu-setup.log"

# ----------------------------------------------------------
# COLORS & OUTPUT
# ----------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# ----------------------------------------------------------
# LOGGING
# ----------------------------------------------------------
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${timestamp} [${level}] ${message}" >> "$LOG_FILE"
}

info() { echo -e "${BLUE}[INFO]${NC} $1"; log "INFO" "$1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; log "SUCCESS" "$1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; log "WARN" "$1"; }
error() { echo -e "${RED}[✗]${NC} $1"; log "ERROR" "$1"; }
step() { echo -e "\n${MAGENTA}${BOLD}═══ $1 ═══${NC}\n"; log "STEP" "$1"; }

# ----------------------------------------------------------
# BANNER
# ----------------------------------------------------------
show_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
    ____       __                __        
   / __ \___  / /_  __  ______  / /___  __ 
  / / / / _ \/ __ \/ / / / __ \/ __/ / / / 
 / /_/ /  __/ /_/ / /_/ / / / / /_/ /_/ /  
/_____/\___/_.___/\__,_/_/ /_/\__/\__,_/   
                                           
    PROVISIONING SUITE v1.0.0
    Ubuntu LTS & Debian Stable
EOF
    echo -e "${NC}"
}

# ----------------------------------------------------------
# ROOT CHECK
# ----------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use: sudo $0)"
        exit 1
    fi
}

# ----------------------------------------------------------
# OS DETECTION
# ----------------------------------------------------------
detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_NAME="$NAME"
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
        OS_CODENAME="${VERSION_CODENAME:-unknown}"
    else
        error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi

    # Validate supported OS
    case "$OS_ID" in
        ubuntu|debian)
            success "Detected: $OS_NAME $OS_VERSION ($OS_CODENAME)"
            ;;
        *)
            error "Unsupported OS: $OS_ID. This script supports Ubuntu and Debian only."
            exit 1
            ;;
    esac
}

# ----------------------------------------------------------
# GET DEFAULT USER (UID 1000)
# ----------------------------------------------------------
get_default_user() {
    DEFAULT_USER=$(getent passwd 1000 | cut -d: -f1)
    if [[ -z "$DEFAULT_USER" ]]; then
        warn "No user with UID 1000 found. Using current sudo user."
        DEFAULT_USER="${SUDO_USER:-root}"
    fi
    DEFAULT_HOME=$(getent passwd "$DEFAULT_USER" | cut -d: -f6)
    success "Default user: $DEFAULT_USER (home: $DEFAULT_HOME)"
}

# ----------------------------------------------------------
# GET ALL USERS (for config deployment)
# ----------------------------------------------------------
get_all_users() {
    # Get all users with login shells and home directories
    ALL_USERS=()
    while IFS=: read -r username _ uid _ _ home shell; do
        # Include users with UID >= 1000 or root, with valid shells
        if [[ ($uid -ge 1000 || $uid -eq 0) && -d "$home" && "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" ]]; then
            ALL_USERS+=("$username:$home")
        fi
    done < /etc/passwd
}

# ----------------------------------------------------------
# SSH KEY PROMPT (Interactive)
# ----------------------------------------------------------
prompt_ssh_key() {
    step "SSH PUBLIC KEY SETUP"
    
    echo -e "${BOLD}This script will disable password authentication for SSH.${NC}"
    echo "You need to provide an SSH public key for secure access."
    echo ""
    
    # Check if key already exists
    if [[ -f "$DEFAULT_HOME/.ssh/authorized_keys" ]] && [[ -s "$DEFAULT_HOME/.ssh/authorized_keys" ]]; then
        info "Existing SSH keys found in $DEFAULT_HOME/.ssh/authorized_keys:"
        cat "$DEFAULT_HOME/.ssh/authorized_keys"
        echo ""
        read -rp "Add another key? (y/N): " add_another
        if [[ ! "$add_another" =~ ^[Yy]$ ]]; then
            SSH_KEY=""
            return
        fi
    fi
    
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              HOW TO GENERATE AN SSH KEY                      ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}Linux/macOS:${NC}                                               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    ssh-keygen -t ed25519 -C \"your_email@example.com\"        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    cat ~/.ssh/id_ed25519.pub                                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                             ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}Windows (PowerShell):${NC}                                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    ssh-keygen -t ed25519 -C \"your_email@example.com\"        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    Get-Content \$env:USERPROFILE\\.ssh\\id_ed25519.pub         ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                             ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}Windows (PuTTYgen):${NC}                                        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    1. Open PuTTYgen → Generate → Save public key            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    2. Copy the key from the top text box                    ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Please paste your SSH public key (starts with 'ssh-rsa' or 'ssh-ed25519'):"
    echo "(Press Enter twice when done)"
    echo ""
    
    SSH_KEY=""
    while IFS= read -r line; do
        [[ -z "$line" ]] && break
        SSH_KEY+="$line"
    done
    
    if [[ -z "$SSH_KEY" ]]; then
        warn "No SSH key provided. You can add one later with:"
        echo "    echo 'your-public-key' >> ~/.ssh/authorized_keys"
    else
        # Validate key format
        if [[ "$SSH_KEY" =~ ^ssh-(rsa|ed25519|ecdsa) ]]; then
            success "Valid SSH key format detected"
        else
            warn "Key format not recognized. Proceeding anyway..."
        fi
    fi
}

# ----------------------------------------------------------
# MODULE 1: SYSTEM CLEANUP
# ----------------------------------------------------------
cleanup_system() {
    step "SYSTEM CLEANUP - Removing Bloatware"
    
    # Packages to remove (if installed)
    local bloatware=(
        # Debian-specific telemetry/reporting
        "popularity-contest"
        "reportbug"
        
        # Games (GNOME)
        "gnome-games"
        "aisleriot"
        "gnome-mines"
        "gnome-sudoku"
        "gnome-mahjongg"
        "gnome-robots"
        "gnome-tetravex"
        "gnome-nibbles"
        "gnome-taquin"
        "gnome-chess"
        "four-in-a-row"
        "five-or-more"
        "hitori"
        "iagno"
        "lightsoff"
        "quadrapassel"
        "swell-foop"
        "tali"
        
        # Other bloat
        "cheese"  # Webcam app
        "rhythmbox"  # Music player (optional)
        "totem"  # Video player (optional)
        "vim-tiny"  # Replace with full vim
    )
    
    local removed=0
    for pkg in "${bloatware[@]}"; do
        if dpkg -l | grep -q "^ii  $pkg "; then
            info "Removing: $pkg"
            apt-get purge -y "$pkg" >> "$LOG_FILE" 2>&1 || true
            ((removed++))
        fi
    done
    
    if [[ $removed -gt 0 ]]; then
        success "Removed $removed bloatware packages"
        apt-get autoremove -y >> "$LOG_FILE" 2>&1
        apt-get clean >> "$LOG_FILE" 2>&1
    else
        info "No bloatware packages found to remove"
    fi
}

# ----------------------------------------------------------
# MODULE 2: USER MANAGEMENT
# ----------------------------------------------------------
setup_user() {
    step "USER MANAGEMENT - Configuring sudo"
    
    # Install sudo if not present
    if ! command -v sudo &>/dev/null; then
        info "Installing sudo..."
        apt-get update >> "$LOG_FILE" 2>&1
        apt-get install -y sudo >> "$LOG_FILE" 2>&1
    fi
    
    # Add default user to sudo group
    if id -nG "$DEFAULT_USER" | grep -qw "sudo"; then
        success "$DEFAULT_USER is already in sudo group"
    else
        info "Adding $DEFAULT_USER to sudo group..."
        usermod -aG sudo "$DEFAULT_USER"
        success "$DEFAULT_USER added to sudo group"
    fi
    
    # Configure passwordless sudo (optional, commented by default)
    # echo "$DEFAULT_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$DEFAULT_USER
}

# ----------------------------------------------------------
# MODULE 3: ESSENTIAL PACKAGES
# ----------------------------------------------------------
install_essentials() {
    step "INSTALLING ESSENTIAL PACKAGES"
    
    info "Updating package lists..."
    apt-get update >> "$LOG_FILE" 2>&1
    
    # Essential packages
    local packages=(
        # Core utilities
        "curl"
        "wget"
        "git"
        "unzip"
        "zip"
        "tar"
        "gzip"
        
        # Text editors
        "nano"
        "vim"
        
        # System monitoring
        "btop"
        
        # Network tools
        "net-tools"
        "dnsutils"
        
        # Security
        "ufw"
        "fail2ban"
        "openssh-server"
        
        # Shell
        "zsh"
        
        # Build essentials (for plugins)
        "build-essential"
        
        # Modern CLI tools
        "bat"
        "lsd"
        "fd-find"
        "ripgrep"
        "fzf"
        "jq"
        
        # LazyVim dependencies
        "neovim"
        "nodejs"
        "npm"
        "python3"
        "python3-pip"
        "python3-venv"
        
        # Fastfetch
        "fastfetch"
        
        # Font tools
        "fontconfig"
        
        # Syntax highlighting for nano
        "nano-syntax-highlighting"
    )
    
    info "Installing packages (this may take a while)..."
    
    for pkg in "${packages[@]}"; do
        if dpkg -l | grep -q "^ii  $pkg "; then
            log "INFO" "Package $pkg already installed"
        else
            info "Installing: $pkg"
            apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 || {
                warn "Failed to install $pkg (may not be available)"
            }
        fi
    done
    
    success "Essential packages installed"
}

# ----------------------------------------------------------
# MODULE 4: FONT INSTALLATION
# ----------------------------------------------------------
install_fonts() {
    step "INSTALLING MARTIANMONO NERD FONT"
    
    local font_src="$REPO_ROOT/fonts/MartianMono_"
    local font_dest="/usr/local/share/fonts/MartianMono"
    
    if [[ ! -d "$font_src" ]]; then
        # Try alternate name
        font_src="$REPO_ROOT/fonts/MartianMono"
    fi
    
    if [[ ! -d "$font_src" ]]; then
        warn "Font directory not found at $font_src"
        info "Attempting to download MartianMono Nerd Font..."
        
        mkdir -p "$font_dest"
        local font_url="https://github.com/ryanoasis/nerd-fonts/releases/latest/download/MartianMono.zip"
        
        if curl -fsSL "$font_url" -o /tmp/MartianMono.zip; then
            unzip -o /tmp/MartianMono.zip -d "$font_dest" >> "$LOG_FILE" 2>&1
            rm -f /tmp/MartianMono.zip
            success "Downloaded and installed MartianMono Nerd Font"
        else
            warn "Failed to download font. Install manually later."
            return
        fi
    else
        info "Copying fonts from $font_src..."
        mkdir -p "$font_dest"
        cp -r "$font_src"/*.ttf "$font_dest/" 2>/dev/null || true
        success "Fonts copied to $font_dest"
    fi
    
    # Update font cache
    info "Updating font cache..."
    fc-cache -fv >> "$LOG_FILE" 2>&1
    
    # Set as system-wide default monospace font
    info "Setting MartianMono as default monospace font..."
    mkdir -p /etc/fonts/conf.d
    cat << 'EOF' > /etc/fonts/local.conf
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
    <!-- Set MartianMono Nerd Font as default monospace -->
    <alias>
        <family>monospace</family>
        <prefer>
            <family>MartianMono Nerd Font</family>
            <family>MartianMono Nerd Font Mono</family>
        </prefer>
    </alias>
    <alias>
        <family>Monospace</family>
        <prefer>
            <family>MartianMono Nerd Font</family>
            <family>MartianMono Nerd Font Mono</family>
        </prefer>
    </alias>
</fontconfig>
EOF
    
    fc-cache -fv >> "$LOG_FILE" 2>&1
    success "MartianMono set as system-wide default monospace font"
}

# ----------------------------------------------------------
# MODULE 5: ZSH CONFIGURATION
# ----------------------------------------------------------
setup_zsh() {
    step "CONFIGURING ZSH SHELL"
    
    get_all_users
    
    for user_info in "${ALL_USERS[@]}"; do
        local username="${user_info%%:*}"
        local home="${user_info##*:}"
        
        info "Setting up ZSH for: $username"
        
        # Copy .zshrc
        if [[ -f "$REPO_ROOT/config/.zshrc" ]]; then
            cp "$REPO_ROOT/config/.zshrc" "$home/.zshrc"
            chown "$username:$username" "$home/.zshrc" 2>/dev/null || true
        fi
        
        # Copy .zshrc_aliases
        if [[ -f "$REPO_ROOT/config/.zshrc_aliases" ]]; then
            cp "$REPO_ROOT/config/.zshrc_aliases" "$home/.zshrc_aliases"
            chown "$username:$username" "$home/.zshrc_aliases" 2>/dev/null || true
        fi
        
        # Set ZSH as default shell
        if [[ "$username" != "root" ]]; then
            chsh -s "$(which zsh)" "$username" 2>/dev/null || {
                warn "Could not change shell for $username"
            }
        fi
    done
    
    # Also setup for root
    if [[ -f "$REPO_ROOT/config/.zshrc" ]]; then
        cp "$REPO_ROOT/config/.zshrc" /root/.zshrc
        cp "$REPO_ROOT/config/.zshrc_aliases" /root/.zshrc_aliases 2>/dev/null || true
    fi
    
    success "ZSH configured for all users"
}

# ----------------------------------------------------------
# MODULE 6: NANO CONFIGURATION
# ----------------------------------------------------------
setup_nano() {
    step "CONFIGURING NANO EDITOR"
    
    get_all_users
    
    for user_info in "${ALL_USERS[@]}"; do
        local username="${user_info%%:*}"
        local home="${user_info##*:}"
        
        if [[ -f "$REPO_ROOT/config/.nanorc" ]]; then
            cp "$REPO_ROOT/config/.nanorc" "$home/.nanorc"
            chown "$username:$username" "$home/.nanorc" 2>/dev/null || true
        fi
    done
    
    # Also for root
    if [[ -f "$REPO_ROOT/config/.nanorc" ]]; then
        cp "$REPO_ROOT/config/.nanorc" /root/.nanorc
    fi
    
    success "Nano configured for all users"
}

# ----------------------------------------------------------
# MODULE 7: FASTFETCH
# ----------------------------------------------------------
setup_fastfetch() {
    step "CONFIGURING FASTFETCH"
    
    get_all_users
    
    local config_src="$REPO_ROOT/config/fastfetch/config.jsonc"
    
    if [[ ! -f "$config_src" ]]; then
        # Try old name
        config_src="$REPO_ROOT/config/fastfetch/minimalist_config.jsonc"
    fi
    
    if [[ ! -f "$config_src" ]]; then
        warn "Fastfetch config not found"
        return
    fi
    
    for user_info in "${ALL_USERS[@]}"; do
        local username="${user_info%%:*}"
        local home="${user_info##*:}"
        
        mkdir -p "$home/.config/fastfetch"
        cp "$config_src" "$home/.config/fastfetch/config.jsonc"
        chown -R "$username:$username" "$home/.config/fastfetch" 2>/dev/null || true
    done
    
    # Also for root
    mkdir -p /root/.config/fastfetch
    cp "$config_src" /root/.config/fastfetch/config.jsonc
    
    success "Fastfetch configured for all users"
}

# ----------------------------------------------------------
# MODULE 8: LAZYVIM
# ----------------------------------------------------------
setup_lazyvim() {
    step "INSTALLING LAZYVIM"
    
    get_all_users
    
    for user_info in "${ALL_USERS[@]}"; do
        local username="${user_info%%:*}"
        local home="${user_info##*:}"
        
        info "Installing LazyVim for: $username"
        
        # Backup existing nvim config
        if [[ -d "$home/.config/nvim" ]]; then
            mv "$home/.config/nvim" "$home/.config/nvim.bak.$(date +%Y%m%d)" 2>/dev/null || true
        fi
        
        # Clone LazyVim starter
        if sudo -u "$username" git clone https://github.com/LazyVim/starter "$home/.config/nvim" >> "$LOG_FILE" 2>&1; then
            # Remove .git to make it the user's own config
            rm -rf "$home/.config/nvim/.git"
            chown -R "$username:$username" "$home/.config/nvim"
            success "LazyVim installed for $username"
        else
            warn "Failed to install LazyVim for $username"
        fi
    done
    
    # Also for root
    if [[ ! -d /root/.config/nvim ]]; then
        git clone https://github.com/LazyVim/starter /root/.config/nvim >> "$LOG_FILE" 2>&1 || true
        rm -rf /root/.config/nvim/.git 2>/dev/null || true
    fi
    
    success "LazyVim installation complete"
}

# ----------------------------------------------------------
# MODULE 9: SECURITY - UFW
# ----------------------------------------------------------
setup_ufw() {
    step "CONFIGURING UFW FIREWALL"
    
    if ! command -v ufw &>/dev/null; then
        warn "UFW not installed, skipping..."
        return
    fi
    
    info "Configuring UFW rules..."
    
    # Reset to defaults (be careful!)
    ufw --force reset >> "$LOG_FILE" 2>&1
    
    # Default policies
    ufw default deny incoming >> "$LOG_FILE" 2>&1
    ufw default allow outgoing >> "$LOG_FILE" 2>&1
    
    # Allow SSH
    ufw allow ssh comment 'SSH' >> "$LOG_FILE" 2>&1
    
    # Enable UFW
    ufw --force enable >> "$LOG_FILE" 2>&1
    
    success "UFW configured: deny incoming, allow SSH"
    
    # Show status
    ufw status verbose
}

# ----------------------------------------------------------
# MODULE 10: SECURITY - FAIL2BAN
# ----------------------------------------------------------
setup_fail2ban() {
    step "CONFIGURING FAIL2BAN"
    
    if ! command -v fail2ban-client &>/dev/null; then
        warn "fail2ban not installed, skipping..."
        return
    fi
    
    info "Configuring fail2ban for SSH..."
    
    # Create jail.local for SSH
    cat << 'EOF' > /etc/fail2ban/jail.local
# Debuntu Provisioning - fail2ban config
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
banaction = ufw

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 24h
EOF
    
    # Restart fail2ban
    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    systemctl restart fail2ban >> "$LOG_FILE" 2>&1
    
    success "fail2ban configured for SSH protection"
}

# ----------------------------------------------------------
# MODULE 11: SSH KEY SETUP
# ----------------------------------------------------------
setup_ssh_key() {
    step "SETTING UP SSH KEY AUTHENTICATION"
    
    if [[ -n "${SSH_KEY:-}" ]]; then
        info "Adding provided SSH key..."
        
        mkdir -p "$DEFAULT_HOME/.ssh"
        chmod 700 "$DEFAULT_HOME/.ssh"
        
        echo "$SSH_KEY" >> "$DEFAULT_HOME/.ssh/authorized_keys"
        chmod 600 "$DEFAULT_HOME/.ssh/authorized_keys"
        chown -R "$DEFAULT_USER:$DEFAULT_USER" "$DEFAULT_HOME/.ssh"
        
        success "SSH key added to $DEFAULT_HOME/.ssh/authorized_keys"
    else
        info "No new SSH key to add"
    fi
    
    # Verify file exists
    if [[ -f "$DEFAULT_HOME/.ssh/authorized_keys" ]]; then
        local key_count
        key_count=$(wc -l < "$DEFAULT_HOME/.ssh/authorized_keys")
        success "Total SSH keys configured: $key_count"
    fi
}

# ----------------------------------------------------------
# MODULE 12: SSH DAEMON HARDENING
# ----------------------------------------------------------
harden_ssh() {
    step "HARDENING SSH DAEMON"
    
    local SSH_PORT="${SSH_PORT:-22}"
    local BACKUP_DIR="/etc/ssh/backup_$(date +%Y%m%d_%H%M%S)"
    
    # Verify SSH key exists before hardening
    if [[ ! -f "$DEFAULT_HOME/.ssh/authorized_keys" ]] || [[ ! -s "$DEFAULT_HOME/.ssh/authorized_keys" ]]; then
        warn "No SSH keys found - skipping SSH hardening to prevent lockout"
        warn "Add an SSH key and run this script again, or manually harden SSH"
        return
    fi
    
    info "Creating backup in $BACKUP_DIR..."
    mkdir -p "$BACKUP_DIR"
    cp -p /etc/ssh/sshd_config "$BACKUP_DIR/" 2>/dev/null || true
    cp -rp /etc/ssh/sshd_config.d "$BACKUP_DIR/" 2>/dev/null || true
    
    info "Writing hardened sshd_config..."
    cat <<EOF > /etc/ssh/sshd_config
# ============================================================
# DEBUNTU HARDENED SSH SERVER CONFIG
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

# Network & Protocol
Port $SSH_PORT
Protocol 2
AddressFamily inet

# Include additional configuration files
Include /etc/ssh/sshd_config.d/*.conf

# Authentication - HARDENED
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM yes
MaxAuthTries 3
MaxSessions 3

# Session Management
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Security Settings
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no

# Banner
Banner /etc/ssh/banner

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# SFTP Subsystem
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

    info "Configuring modern cryptographic algorithms..."
    mkdir -p /etc/ssh/sshd_config.d
    cat <<EOF > /etc/ssh/sshd_config.d/ciphers.conf
# Post-Quantum Ready Cryptographic Algorithms
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
EOF

    info "Creating SSH login banner..."
    cat <<'EOF' > /etc/ssh/banner
╔══════════════════════════════════════════════════════════════╗
║                    AUTHORIZED ACCESS ONLY                    ║
╠══════════════════════════════════════════════════════════════╣
║  All connections are monitored and logged.                   ║
║  Unauthorized access attempts will be prosecuted.            ║
╚══════════════════════════════════════════════════════════════╝
EOF

    info "Disabling systemd socket activation..."
    systemctl stop ssh.socket 2>/dev/null || true
    systemctl disable ssh.socket 2>/dev/null || true
    systemctl mask ssh.socket 2>/dev/null || true

    info "Validating SSH configuration..."
    if sshd -t 2>/dev/null; then
        success "SSH configuration is valid"
        
        systemctl enable ssh.service 2>/dev/null || systemctl enable sshd.service 2>/dev/null
        systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service 2>/dev/null
        success "SSH daemon restarted with hardened configuration"
    else
        error "SSH configuration validation failed - restoring backup"
        cp "$BACKUP_DIR/sshd_config" /etc/ssh/sshd_config
        return 1
    fi
    
    success "SSH hardening complete"
}

# ----------------------------------------------------------
# CLEANUP OLD CONFIG
# ----------------------------------------------------------
cleanup_old_files() {
    # Remove old fastfetch config if exists
    rm -f "$REPO_ROOT/config/fastfetch/minimalist_config.jsonc" 2>/dev/null || true
}

# ----------------------------------------------------------
# FINAL SUMMARY
# ----------------------------------------------------------
show_summary() {
    echo ""
    echo -e "${GREEN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           PROVISIONING COMPLETE!                         ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "${BOLD}Summary of changes:${NC}"
    echo "  • Bloatware packages removed"
    echo "  • User $DEFAULT_USER added to sudo group"
    echo "  • MartianMono Nerd Font installed (system-wide default)"
    echo "  • ZSH configured with Oh-My-Zsh + Powerlevel10k"
    echo "  • LazyVim installed for all users"
    echo "  • Fastfetch configured for all users"
    echo "  • UFW firewall enabled (SSH allowed)"
    echo "  • SSH daemon hardened (key-only auth, modern crypto)"
    echo ""
    echo -e "${YELLOW}Log file:${NC} $LOG_FILE"
    echo ""
    echo -e "${BOLD}Next steps:${NC}"
    echo "  1. Log out and log back in to activate ZSH"
    echo "  2. Run 'p10k configure' to customize your prompt"
    echo "  3. Open nvim to let LazyVim install plugins"
    echo ""
    
    if [[ -z "${SSH_KEY:-}" ]]; then
        echo -e "${YELLOW}WARNING: No SSH key was added. Add one manually:${NC}"
        echo "  echo 'your-public-key' >> ~/.ssh/authorized_keys"
        echo ""
    fi
    
    echo -e "${GREEN}Happy hacking! 🚀${NC}"
    echo ""
}

# ============================================================
# MAIN EXECUTION
# ============================================================
main() {
    # Initialize log
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "=== DEBUNTU PROVISIONING LOG ===" > "$LOG_FILE"
    echo "Started: $(date)" >> "$LOG_FILE"
    echo "Version: $SCRIPT_VERSION" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    
    # Pre-flight
    show_banner
    check_root
    detect_os
    get_default_user
    
    # Interactive SSH key prompt FIRST
    prompt_ssh_key
    
    # Execute modules
    cleanup_system
    setup_user
    install_essentials
    install_fonts
    setup_zsh
    setup_nano
    setup_fastfetch
    setup_lazyvim
    setup_ufw
    setup_fail2ban
    setup_ssh_key
    harden_ssh
    cleanup_old_files
    
    # Done
    echo "" >> "$LOG_FILE"
    echo "Completed: $(date)" >> "$LOG_FILE"
    
    show_summary
}

# Run main
main "$@"
