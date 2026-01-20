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

# Only use -u to catch unset variables. -e causes issues with apt commands.
set -u

# ----------------------------------------------------------
# CRITICAL: Prevent apt from asking questions
# ----------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none

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
# CRITICAL DEPENDENCY CHECK
# ----------------------------------------------------------
check_dependencies() {
    local missing_deps=()
    
    if ! command -v curl &>/dev/null; then
        missing_deps+=("curl")
    fi
    
    if ! command -v git &>/dev/null; then
        missing_deps+=("git")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        warn "Missing dependencies: ${missing_deps[*]}"
        warn "Script will attempt to install them or fall back to alternatives."
    else
        success "Critical dependencies found (curl, git)"
    fi
}

# ----------------------------------------------------------
# ENSURE REPO (Self-Bootstrapping for Curl Pipe)
# ----------------------------------------------------------
ensure_repo() {
    if [[ ! -d "$REPO_ROOT/config" ]]; then
        info "Running in standalone mode. Cloning repository for configuration..."
        local temp_dir="/tmp/debuntu_provisionning_$(date +%s)"
        git clone https://github.com/Likkyh/Debuntu_provisionning.git "$temp_dir" >> "$LOG_FILE" 2>&1 || {
            error "Failed to clone repository. Cannot continue."
            exit 1
        }
        REPO_ROOT="$temp_dir"
        success "Repository cloned to $REPO_ROOT"
    fi
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
    echo -e "${YELLOW}To SKIP, just press Enter twice (no SSH key will be added).${NC}"
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
# KEYBOARD LOCALE PRESERVATION
# This is CRITICAL - apt can silently reconfigure keyboard
# ----------------------------------------------------------
KEYBOARD_BACKED_UP=false

backup_keyboard_locale() {
    step "BACKING UP KEYBOARD LOCALE"
    
    if [[ -f /etc/default/keyboard ]]; then
        cp -f /etc/default/keyboard /etc/default/keyboard.debuntu.bak
        # Also save the actual content so we can verify
        cat /etc/default/keyboard > /tmp/keyboard_original.txt
        KEYBOARD_BACKED_UP=true
        success "Keyboard locale backed up"
        info "Current keyboard config:"
        grep -E "^XKBLAYOUT|^XKBVARIANT" /etc/default/keyboard || true
    else
        info "No keyboard configuration found to backup"
    fi
    
    # Also backup console-setup if present
    if [[ -f /etc/default/console-setup ]]; then
        cp -f /etc/default/console-setup /etc/default/console-setup.debuntu.bak
    fi
    
    # Mark keyboard-configuration package to not be auto-configured
    if command -v debconf-set-selections &>/dev/null; then
        echo "keyboard-configuration keyboard-configuration/layoutcode string $(grep XKBLAYOUT /etc/default/keyboard 2>/dev/null | cut -d'"' -f2 || echo 'us')" | debconf-set-selections 2>/dev/null || true
    fi
}

restore_keyboard_locale() {
    # ALWAYS restore keyboard config - don't check if it changed
    if [[ -f /etc/default/keyboard.debuntu.bak ]]; then
        info "Restoring keyboard locale..."
        cp -f /etc/default/keyboard.debuntu.bak /etc/default/keyboard
        # Apply the keyboard configuration
        setupcon --force 2>/dev/null || true
        udevadm trigger --subsystem-match=input --action=change 2>/dev/null || true
        success "Keyboard locale restored"
    fi
    
    # Same for console-setup
    if [[ -f /etc/default/console-setup.debuntu.bak ]]; then
        cp -f /etc/default/console-setup.debuntu.bak /etc/default/console-setup
    fi
}

# CRITICAL: Set up trap to ALWAYS restore keyboard on exit
cleanup_on_exit() {
    local exit_code=$?
    if [[ "$KEYBOARD_BACKED_UP" == "true" ]]; then
        echo "" >> "$LOG_FILE" 2>/dev/null || true
        echo "Restoring keyboard locale on exit..." >> "$LOG_FILE" 2>/dev/null || true
        restore_keyboard_locale
    fi
    exit $exit_code
}
trap cleanup_on_exit EXIT

# ----------------------------------------------------------
# DESKTOP ENVIRONMENT PROTECTION
# ----------------------------------------------------------
protect_desktop_packages() {
    step "PROTECTING DESKTOP ENVIRONMENT"
    
    info "Marking essential desktop packages as manually installed..."
    
    # Comprehensive list of GNOME/desktop packages to protect
    local desktop_packages=(
        # GNOME core
        "gnome-shell"
        "gdm3"
        "gnome-session"
        "gnome-session-bin"
        "gnome-terminal"
        "gnome-control-center"
        "mutter"
        "gnome-settings-daemon"
        "nautilus"
        "gnome-desktop3-data"
        
        # X.org
        "xorg"
        "xserver-xorg"
        "xserver-xorg-core"
        "xserver-xorg-input-all"
        "xserver-xorg-video-all"
        
        # Display managers
        "gdm3"
        "lightdm"
        
        # Desktop meta-packages
        "ubuntu-desktop"
        "ubuntu-desktop-minimal"
        "gnome"
        "gnome-core"
        "task-gnome-desktop"
        "task-desktop"
        
        # Keyboard/locale packages
        "keyboard-configuration"
        "console-setup"
        "console-setup-linux"
        "xkb-data"
    )
    
    for pkg in "${desktop_packages[@]}"; do
        apt-mark manual "$pkg" >> "$LOG_FILE" 2>&1 || true
    done
    
    # CRITICAL: Protect boot-essential packages by marking as manually installed
    # NOTE: We do NOT use 'apt-mark hold' on grub packages as this can cause
    # boot failures when apt tries to reconfigure packages during other operations.
    # Instead, we mark them as manual to prevent autoremove from touching them.
    info "Protecting boot-critical packages..."
    
    # Find and mark kernel packages as manually installed
    local kernel_pkgs
    kernel_pkgs=$(dpkg -l 2>/dev/null | grep "^ii" | awk '{print $2}' | grep -E "^linux-image-|^linux-headers-" || true)
    
    if [[ -n "$kernel_pkgs" ]]; then
        while IFS= read -r pkg; do
            apt-mark manual "$pkg" >> "$LOG_FILE" 2>&1 || true
        done <<< "$kernel_pkgs"
    fi
    
    # Mark other critical boot packages as manually installed
    # This prevents autoremove from ever considering them for removal
    local boot_packages=(
        # Bootloader (NEVER hold these - causes boot issues)
        "grub-pc"
        "grub-efi-amd64"
        "grub-efi-amd64-signed"
        "grub-common"
        "grub2-common"
        "shim-signed"
        
        # Initramfs and boot
        "initramfs-tools"
        "initramfs-tools-core"
        "linux-base"
        
        # System essentials
        "systemd"
        "systemd-sysv"
        "dbus"
        "dbus-user-session"
        "efibootmgr"
    )
    
    for pkg in "${boot_packages[@]}"; do
        apt-mark manual "$pkg" >> "$LOG_FILE" 2>&1 || true
    done
    
    success "Desktop and boot-critical packages protected"
}

# ----------------------------------------------------------
# BOOTLOADER VERIFICATION
# ----------------------------------------------------------
ensure_bootloader() {
    step "ENSURING BOOTLOADER MBR/EFI"
    
    # 1. Detect Boot Mechanism
    if [[ -d /sys/firmware/efi ]]; then
        info "EFI System Detected."
        # Ensure packages
        apt-get install -y --no-remove grub-efi-amd64 grub-efi-amd64-signed shim-signed || true
        # Install to EFI vars
        info "Running grub-install..."
        grub-install >> "$LOG_FILE" 2>&1 || warn "grub-install failed"
    else
        info "Legacy BIOS Detected."
        apt-get install -y --no-remove grub-pc || true
        
        # Detect Disk
        local boot_part=$(findmnt / -n -o SOURCE)
        local boot_disk=$(echo "$boot_part" | sed 's/[0-9]*$//')
        
        # Handle NVMe (/dev/nvme0n1p1 -> /dev/nvme0n1)
        if [[ "$boot_disk" == *"nvme"* ]] && [[ "$boot_disk" == *"p" ]]; then
             boot_disk=${boot_disk%p}
        fi
        
        if [[ -b "$boot_disk" ]]; then
            info "Installing GRUB to $boot_disk..."
            grub-install "$boot_disk" >> "$LOG_FILE" 2>&1 || warn "grub-install to $boot_disk failed"
        else
            warn "Could not verify boot disk (detected: $boot_disk). Skipping grub-install."
        fi
    fi
    
    # Update Config
    update-grub >> "$LOG_FILE" 2>&1 || warn "update-grub failed"
    success "Bootloader refreshed."
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
        
        "vim-tiny"  # Replace with full vim
        
        # Extended Bloatware (Camera, Calendar, etc)
        "cheese"
        "gnome-calendar"
        "gnome-contacts"
        "gnome-maps"
        "gnome-weather"
        "simple-scan"
        "snapshot"
        "yelp" # Help viewer
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
        
        # Protect essential desktop packages from autoremove
        info "Protecting essential desktop packages..."
        local desktop_packages=(
            "gnome-shell"
            "gdm3"
            "gnome-session"
            "gnome-terminal"
            "gnome-control-center"
            "mutter"
            "gnome-settings-daemon"
            "nautilus"
            "xorg"
            "xserver-xorg"
        )
        for pkg in "${desktop_packages[@]}"; do
            apt-mark manual "$pkg" >> "$LOG_FILE" 2>&1 || true
        done
        
        # SAFE AUTOREMOVE: Check what would be removed before actually removing
        info "Checking packages to autoremove..."
        local autoremove_list
        autoremove_list=$(apt-get autoremove --simulate 2>/dev/null | grep "^Remv " | awk '{print $2}' || true)
        
        # Check if any critical packages would be removed
        local critical_patterns="grub|linux-image|linux-headers|systemd|initramfs|gnome-shell|gdm3|xserver|mutter"
        local dangerous_pkgs
        dangerous_pkgs=$(echo "$autoremove_list" | grep -E "$critical_patterns" || true)
        
        if [[ -n "$dangerous_pkgs" ]]; then
            warn "SKIPPING autoremove - would remove critical packages:"
            echo "$dangerous_pkgs" | while read -r pkg; do
                warn "  - $pkg"
            done
            log "WARN" "Autoremove skipped - dangerous packages: $dangerous_pkgs"
        elif [[ -n "$autoremove_list" ]]; then
            info "Autoremove will clean: $(echo "$autoremove_list" | wc -w) packages"
            apt-get autoremove -y >> "$LOG_FILE" 2>&1 || true
            success "Autoremove completed safely"
        else
            info "No packages to autoremove"
        fi
        
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
# SAFE INSTALL FUNCTION (Prevents Crash Loops)
# ----------------------------------------------------------
# ----------------------------------------------------------
# SAFE INSTALL FUNCTION (Prevents Crash Loops)
# ----------------------------------------------------------
safe_install() {
    local pkgs=("$@")
    local pkg_str="${pkgs[*]}"
    
    info "Installing: $pkg_str"
    
    # 1. SIMULATE
    local sim_out
    sim_out=$(apt-get install --simulate --no-install-recommends "${pkgs[@]}" 2>&1)
    
    if echo "$sim_out" | grep -q "^Remv"; then
        warn "CRITICAL: Installing '$pkg_str' would remove packages! skipping..."
        echo "$sim_out" | grep "^Remv" | while read -r line; do
            warn "  $line"
        done
        return 1 # Fail gracefully instead of aborting
    fi
    
    # 2. INSTALL
    if apt-get install -y --no-install-recommends --no-remove "${pkgs[@]}" >> "$LOG_FILE" 2>&1; then
        success "Installed: $pkg_str"
        sync
    else
        warn "Failed to install: $pkg_str. Checking logs..."
        return 1
    fi
}

# ----------------------------------------------------------
# STATIC CURL INSTALLER (Fallback)
# ----------------------------------------------------------
install_static_curl() {
    # Tries apt first, then static binary
    if safe_install curl; then
        return 0
    fi
    
    warn "apt-get install curl failed. Attempting static binary install..."
    
    # Static binary from moparisthebest/static-curl
    local static_url="https://github.com/moparisthebest/static-curl/releases/latest/download/curl-amd64"
    
    # We need a downloader. Python is usually present.
    local dl_cmd=""
    if command -v python3 &>/dev/null; then
        dl_cmd="python3 -c \"import urllib.request; urllib.request.urlretrieve('$static_url', '/usr/local/bin/curl')\""
    elif command -v wget &>/dev/null; then
        dl_cmd="wget -O /usr/local/bin/curl $static_url"
    else
        error "No way to download static curl (python3/wget missing)"
        return 1
    fi
    
    info "Downloading static curl..."
    if eval "$dl_cmd"; then
        chmod +x /usr/local/bin/curl
        hash -r 2>/dev/null || true
        success "Static curl installed to /usr/local/bin/curl"
    else
        error "Failed to download static curl"
        return 1
    fi
}

# ----------------------------------------------------------
# MODULE 3: ESSENTIAL PACKAGES
# ----------------------------------------------------------
install_essentials() {
    step "INSTALLING ESSENTIAL PACKAGES"
    
    info "Stopping unattended-upgrades to prevent lock conflicts..."
    systemctl stop unattended-upgrades 2>/dev/null || true
    
    dpkg --configure -a >> "$LOG_FILE" 2>&1 || true
    
    info "Updating package lists..."
    apt-get update --allow-releaseinfo-change >> "$LOG_FILE" 2>&1 || {
        warn "apt-get update returned error, trying standard update..."
        apt-get update >> "$LOG_FILE" 2>&1 || warn "apt-get update failed"
    }

    info "Performing safe package list update..."
    apt-get update >> "$LOG_FILE" 2>&1 || warn "apt-get update failed"
    
    info "Installing packages one-by-one for safety..." 
    
    # 1. Critical Tools
    # Note: curl is checked at start, but we update it here if possible
    install_static_curl || warn "Curl installation failed"
    safe_install wget
    safe_install git
    safe_install unzip zip
    safe_install gzip tar
    
    # 2. Editors & Shell
    safe_install nano vim
    safe_install zsh
    
    # 3. Security & Net
    safe_install ufw
    safe_install fail2ban 
    safe_install openssh-server
    safe_install net-tools dnsutils
    
    # 4. Monitoring & Build
    safe_install btop
    safe_install build-essential
    
    # 5. Modern Tools
    safe_install fzf jq
    safe_install bat || true
    safe_install lsd || true
    safe_install ripgrep || true
    safe_install fd-find || true
    safe_install fastfetch || true
    
    # 6. Dev Tools
    safe_install python3 python3-pip python3-venv
    safe_install nodejs npm
    safe_install neovim
    
    # 7. Sys
    safe_install fontconfig
    
    success "Essential packages installation completed"
}

# ----------------------------------------------------------
# MODULE 4: FONT INSTALLATION (via Nerd Fonts CLI)
# ----------------------------------------------------------
install_fonts() {
    step "INSTALLING MARTIANMONO NERD FONT"
    
    local font_dest="/usr/local/share/fonts/NerdFonts"
    
    info "Installing MartianMono Nerd Font via official installer..."
    
    # Use the official Nerd Fonts install script
    # This downloads and installs fonts to ~/.local/share/fonts by default
    # We'll install system-wide instead
    
    mkdir -p "$font_dest"
    
    # Download MartianMono directly from Nerd Fonts releases
    local font_url="https://github.com/ryanoasis/nerd-fonts/releases/latest/download/MartianMono.zip"
    local temp_zip="/tmp/MartianMono.zip"
    
    info "Downloading MartianMono Nerd Font..."
    
    if curl -fsSL "$font_url" -o "$temp_zip"; then
        info "Download successful"
    else
        error "Failed to download fonts"
        return 0
    fi
    
    info "Extracting fonts..."
    unzip -o "$temp_zip" -d "$font_dest" >> "$LOG_FILE" 2>&1
    rm -f "$temp_zip"
    success "MartianMono Nerd Font installed to $font_dest"
    
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
# MODULE 4.5: TERMINAL CONFIGURATION
# ----------------------------------------------------------
setup_terminal() {
    step "CONFIGURING TERMINAL PROFILE"
    
    get_all_users
    for user_info in "${ALL_USERS[@]}"; do
        local username="${user_info%%:*}"
        
        # Configure GNOME Terminal if present
        if command -v gsettings &>/dev/null; then
             info "Setting MartianMono font for $username..."
             
             # 1. Set System-wide Monospace Font (Interfaces)
             # This is the most robust way - terminal usually follows system font
             sudo -u "$username" dbus-launch gsettings set org.gnome.desktop.interface monospace-font-name 'MartianMono Nerd Font 11' 2>/dev/null || true
             
             # 2. Force Terminal to use System Font (UUID dance)
             sudo -u "$username" dbus-launch bash -c '
                uuid=$(gsettings get org.gnome.Terminal.ProfilesList default | tr -d "\047")
                
                # Force "Use system font"
                gsettings set "org.gnome.Terminal.Legacy.Profile:/org/gnome/terminal/legacy/profiles:/:$uuid/" use-system-font true
                
                # Backup: explicitly set font just in case
                gsettings set "org.gnome.Terminal.Legacy.Profile:/org/gnome/terminal/legacy/profiles:/:$uuid/" font "MartianMono Nerd Font 11"
             ' 2>/dev/null || true
        fi
    done
    success "Terminal and System Monospace font updated"
}

# ----------------------------------------------------------
# MODULE 4.6: CONSOLE FONT (Headless/TTY)
# ----------------------------------------------------------
setup_console() {
    step "CONFIGURING CONSOLE FONT"
    
    # MartianMono cannot be used directly in TTY (needs PSF)
    # We will use Terminus if available, which is clean and readable
    
    if ! dpkg -l | grep -q "console-setup"; then
        safe_install console-setup
    fi
    
    if [[ -f /etc/default/console-setup ]]; then
        info "Setting console font to Terminus..."
        # Update config
        sed -i 's/^FONTFACE=.*/FONTFACE="Terminus"/' /etc/default/console-setup
        sed -i 's/^FONTSIZE=.*/FONTSIZE="16x32"/' /etc/default/console-setup
        
        # Apply
        setupcon --force >> "$LOG_FILE" 2>&1 || true
        success "Console font updated (Terminus)"
    else
        warn "console-setup not found, skipping TTY font config"
    fi
}

# ----------------------------------------------------------
# MODULE 5: ZSH CONFIGURATION
# ----------------------------------------------------------
setup_zsh() {
    step "CONFIGURING ZSH SHELL"
    
    # INSTALL OH-MY-ZSH & PLUGINS EXPLICITLY
    # (Don't rely on .zshrc auto-install which often fails)
    
    # 1. Critical Tools
    # Note: curl is checked at start, but we update it here if possible
    install_static_curl || warn "Curl installation failed"
    safe_install wget
    safe_install git
    safe_install unzip zip
    safe_install gzip tar
    
    # 2. Editors & Shell
    safe_install nano vim
    safe_install zsh
    
    # 3. Security & Net
    safe_install ufw
    safe_install fail2ban 
    safe_install openssh-server
    safe_install net-tools dnsutils
    
    # 4. Monitoring & Build
    safe_install btop
    safe_install build-essential
    
    # 5. Modern Tools
    safe_install fzf jq
    safe_install bat || true
    safe_install lsd || true
    safe_install ripgrep || true
    safe_install fd-find || true
    safe_install fastfetch || true
    
    # 6. Dev Tools
    safe_install python3 python3-pip python3-venv
    safe_install nodejs npm
    safe_install neovim
    
    # 7. Sys
    safe_install fontconfig
    
    success "Essential packages installation completed"
}

# ----------------------------------------------------------
# MODULE 4: FONT INSTALLATION (via Nerd Fonts CLI)
# ----------------------------------------------------------
install_fonts() {
    step "INSTALLING MARTIANMONO NERD FONT"
    
    local font_dest="/usr/local/share/fonts/NerdFonts"
    
    info "Installing MartianMono Nerd Font via official installer..."
    
    # Use the official Nerd Fonts install script
    # This downloads and installs fonts to ~/.local/share/fonts by default
    # We'll install system-wide instead
    
    mkdir -p "$font_dest"
    
    # Download MartianMono directly from Nerd Fonts releases
    local font_url="https://github.com/ryanoasis/nerd-fonts/releases/latest/download/MartianMono.zip"
    local temp_zip="/tmp/MartianMono.zip"
    
    info "Downloading MartianMono Nerd Font..."
    
    if curl -fsSL "$font_url" -o "$temp_zip"; then
        info "Download successful"
    else
        error "Failed to download fonts"
        return 0
    fi
    
    info "Extracting fonts..."
    unzip -o "$temp_zip" -d "$font_dest" >> "$LOG_FILE" 2>&1
    rm -f "$temp_zip"
    success "MartianMono Nerd Font installed to $font_dest"
    
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
    
    # INSTALL OH-MY-ZSH & PLUGINS EXPLICITLY
    # (Don't rely on .zshrc auto-install which often fails)
    
    # 1. Install for DEFAULT USER (vboxuser, etc)
    local target_user="$DEFAULT_USER"
    local target_home="$DEFAULT_HOME"
    
    info "Installing Oh-My-Zsh for $target_user..."
    
    # Install OMZ
    if [[ ! -d "$target_home/.oh-my-zsh" ]]; then
        # Use sudo -u to install as the user (permissions!)
        # Use --unattended to prevent switching shell immediately
        sudo -u "$target_user" sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended >> "$LOG_FILE" 2>&1 || {
             warn "OMZ install script failed. Trying manual clone..."
             sudo -u "$target_user" git clone --depth=1 https://github.com/ohmyzsh/ohmyzsh.git "$target_home/.oh-my-zsh" >> "$LOG_FILE" 2>&1
        }
    fi
    
    # Install Powerlevel10k
    local p10k_dir="$target_home/.oh-my-zsh/custom/themes/powerlevel10k"
    if [[ ! -d "$p10k_dir" ]]; then
        info "Installing Powerlevel10k..."
        sudo -u "$target_user" git clone --depth=1 https://github.com/romkatv/powerlevel10k.git "$p10k_dir" >> "$LOG_FILE" 2>&1 || true
    fi
    
    # Install Plugins
    local plugins_dir="$target_home/.oh-my-zsh/custom/plugins"
    mkdir -p "$plugins_dir"
    
    info "Installing ZSH plugins..."
    if [[ ! -d "$plugins_dir/zsh-autosuggestions" ]]; then
        sudo -u "$target_user" git clone https://github.com/zsh-users/zsh-autosuggestions "$plugins_dir/zsh-autosuggestions" >> "$LOG_FILE" 2>&1 || true
    fi
    
    if [[ ! -d "$plugins_dir/zsh-syntax-highlighting" ]]; then
        sudo -u "$target_user" git clone https://github.com/zsh-users/zsh-syntax-highlighting.git "$plugins_dir/zsh-syntax-highlighting" >> "$LOG_FILE" 2>&1 || true
    fi
    
    # 2. Deploy Configuration Files
    info "Deploying .zshrc configuration..."
    get_all_users
    for user_info in "${ALL_USERS[@]}"; do
        local username="${user_info%%:*}"
        local home="${user_info##*:}"
        
        # Deploy .zshrc
        if [[ -f "$REPO_ROOT/config/.zshrc" ]]; then
            cp "$REPO_ROOT/config/.zshrc" "$home/.zshrc"
            chown "$username:$username" "$home/.zshrc" 2>/dev/null || true
        fi
        
        # Deploy .zshrc_aliases
        if [[ -f "$REPO_ROOT/config/.zshrc_aliases" ]]; then
            cp "$REPO_ROOT/config/.zshrc_aliases" "$home/.zshrc_aliases"
            chown "$username:$username" "$home/.zshrc_aliases" 2>/dev/null || true
        fi
        
        # Deploy .p10k.zsh
        if [[ -f "$REPO_ROOT/config/.p10k.zsh" ]]; then
            cp "$REPO_ROOT/config/.p10k.zsh" "$home/.p10k.zsh"
            chown "$username:$username" "$home/.p10k.zsh" 2>/dev/null || true
        fi
        
        # Set ZSH as default shell
        if [[ "$username" != "root" ]]; then
            chsh -s "$(which zsh)" "$username" 2>/dev/null || true
        fi
    done
    
    # Also setup for root (optional, minimalist)
    if [[ -f "$REPO_ROOT/config/.zshrc" ]]; then
        cp "$REPO_ROOT/config/.zshrc" /root/.zshrc
        cp "$REPO_ROOT/config/.zshrc_aliases" /root/.zshrc_aliases 2>/dev/null || true
    fi
    
    success "ZSH configured successfully"
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
    
    local config_dir="$REPO_ROOT/config/fastfetch"
    
    if [[ ! -d "$config_dir" ]]; then
        warn "Fastfetch config dir not found"
        return
    fi
    
    for user_info in "${ALL_USERS[@]}"; do
        local username="${user_info%%:*}"
        local home="${user_info##*:}"
        local user_config_dir="$home/.config/fastfetch"
        
        mkdir -p "$user_config_dir"
        # Copy config AND images
        cp -r "$config_dir/"* "$user_config_dir/"
        chown -R "$username:$username" "$user_config_dir" 2>/dev/null || true
    done
    
    # Also for root
    mkdir -p /root/.config/fastfetch
    cp -r "$config_dir/"* /root/.config/fastfetch/
    
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
# DARK MODE CONFIGURATION - REMOVED (Headless Server Focus)
# ----------------------------------------------------------
# setup_dark_mode() { ... }

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
    check_dependencies # Verify curl/git are present
    ensure_repo        # Auto-clone if running standalone
    get_default_user
    
    # PROTECT DESKTOP IMMEDIATELY - before any package operations
    protect_desktop_packages
    backup_keyboard_locale
    
    # Interactive SSH key prompt
    prompt_ssh_key
    
    # Execute modules
    cleanup_system
    setup_user
    install_essentials
    ensure_bootloader # Enforce bootloader installation directly
    install_fonts
    setup_terminal
    setup_console
    setup_zsh
    setup_nano
    setup_fastfetch
    # setup_dark_mode (removed)
    setup_lazyvim
    setup_ufw
    setup_fail2ban
    setup_ssh_key
    harden_ssh
    cleanup_old_files
    
    # Restore keyboard locale if it was modified
    restore_keyboard_locale
    
    # Done
    echo "" >> "$LOG_FILE"
    echo "Completed: $(date)" >> "$LOG_FILE"
    
    show_summary
}

# Run main
main "$@"
