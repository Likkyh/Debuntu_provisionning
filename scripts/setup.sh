#!/bin/bash
# ============================================================
# DEBUNTU PROVISIONING SCRIPT
# Production-ready setup for Ubuntu LTS and Debian Stable VMs
# ============================================================
#
# FEATURES:
# - Removes bloatware and unnecessary packages
# - Installs MartianMono Nerd Font (system-wide default)
# - Sets up ZSH with Oh-My-Zsh and Powerlevel10k
# - Deploys fastfetch with custom config
# - Hardens SSH with key-based authentication (if key provided)
# - Configures UFW firewall and fail2ban
#
# USAGE:
#   Local:  sudo ./setup.sh
#   Remote: curl -fsSL <raw-url>/scripts/setup.sh | sudo bash
#
# Idempotent: safe to run multiple times.
# ============================================================

# Catch unset variables and broken pipes. No set -e (apt often returns non-zero).
set -uo pipefail

# ----------------------------------------------------------
# CRITICAL: Prevent apt from asking questions
# ----------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none

# ----------------------------------------------------------
# SCRIPT METADATA
# ----------------------------------------------------------
SCRIPT_VERSION="2.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/var/log/debuntu-setup.log"

# Globals populated later
ALL_USERS=()
SSH_KEY=""
KEYBOARD_BACKED_UP=false

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
    local level="$1" message="$2"
    printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$message" >> "$LOG_FILE"
}

info()    { echo -e "${BLUE}[INFO]${NC} $1"; log "INFO" "$1"; }
success() { echo -e "${GREEN}[OK]${NC} $1";  log "OK"   "$1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1";  log "WARN" "$1"; }
error()   { echo -e "${RED}[X]${NC} $1";     log "ERR"  "$1"; }
step()    { echo -e "\n${MAGENTA}${BOLD}=== $1 ===${NC}\n"; log "STEP" "$1"; }

# ----------------------------------------------------------
# BANNER
# ----------------------------------------------------------
show_banner() {
    echo -e "${CYAN}"
    cat << 'BANNER'
    ____       __                __
   / __ \___  / /_  __  ______  / /___  __
  / / / / _ \/ __ \/ / / / __ \/ __/ / / /
 / /_/ /  __/ /_/ / /_/ / / / / /_/ /_/ /
/_____/\___/_.___/\__,_/_/ /_/\__/\__,_/

    PROVISIONING SUITE v2.0.0
    Ubuntu LTS & Debian Stable
BANNER
    echo -e "${NC}"
}

# ----------------------------------------------------------
# PREFLIGHT CHECKS
# ----------------------------------------------------------
preflight_checks() {
    step "PREFLIGHT CHECKS"

    # Root check
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use: sudo $0)"
        exit 1
    fi

    # OS detection
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    OS_CODENAME="${VERSION_CODENAME:-unknown}"

    case "$OS_ID" in
        ubuntu|debian)
            success "Detected: ${NAME:-$OS_ID} $OS_VERSION ($OS_CODENAME)"
            ;;
        *)
            error "Unsupported OS: $OS_ID. Only Ubuntu and Debian are supported."
            exit 1
            ;;
    esac

    # Minimal dependency check (curl/git will be installed later if missing)
    local have_curl=false have_git=false
    command -v curl &>/dev/null && have_curl=true
    command -v git  &>/dev/null && have_git=true
    if $have_curl && $have_git; then
        success "Critical dependencies present (curl, git)"
    else
        warn "Missing: $( $have_curl || echo 'curl' ) $( $have_git || echo 'git' ) — will install"
    fi
}

# ----------------------------------------------------------
# GET USERS — called once, result cached in ALL_USERS
# ----------------------------------------------------------
get_users() {
    ALL_USERS=()
    while IFS=: read -r username _ uid _ _ home shell; do
        if [[ ($uid -ge 1000 || $uid -eq 0) && -d "$home" \
              && "$shell" != "/usr/sbin/nologin" \
              && "$shell" != "/bin/false" ]]; then
            ALL_USERS+=("$username:$home")
        fi
    done < /etc/passwd

    if [[ ${#ALL_USERS[@]} -eq 0 ]]; then
        warn "No eligible users found — falling back to root"
        ALL_USERS=("root:/root")
    fi

    local names=()
    for entry in "${ALL_USERS[@]}"; do names+=("${entry%%:*}"); done
    success "Target users: ${names[*]}"
}

# ----------------------------------------------------------
# ENSURE REPO (self-bootstrap for curl|bash)
# ----------------------------------------------------------
ensure_repo() {
    if [[ -d "$REPO_ROOT/config" ]]; then
        return
    fi

    info "Running in standalone mode — cloning repository..."

    # Need git; install it if absent
    if ! command -v git &>/dev/null; then
        apt-get update -qq >> "$LOG_FILE" 2>&1 || true
        apt-get install -y -qq git >> "$LOG_FILE" 2>&1 || {
            error "Cannot install git. Aborting."
            exit 1
        }
    fi

    local temp_dir="/tmp/debuntu_provisionning_$$"
    if git clone --depth=1 https://github.com/Likkyh/Debuntu_provisionning.git "$temp_dir" >> "$LOG_FILE" 2>&1; then
        REPO_ROOT="$temp_dir"
        success "Repository cloned to $REPO_ROOT"
    else
        error "Failed to clone repository. Cannot continue."
        exit 1
    fi
}

# ----------------------------------------------------------
# PROMPT SSH KEY (interactive)
# ----------------------------------------------------------
prompt_ssh_key() {
    step "SSH PUBLIC KEY SETUP"

    # Find first non-root user's home for existing key check
    local first_home=""
    for entry in "${ALL_USERS[@]}"; do
        local u="${entry%%:*}" h="${entry##*:}"
        if [[ "$u" != "root" ]]; then first_home="$h"; break; fi
    done
    first_home="${first_home:-/root}"

    if [[ -f "$first_home/.ssh/authorized_keys" && -s "$first_home/.ssh/authorized_keys" ]]; then
        info "Existing SSH keys found in $first_home/.ssh/authorized_keys:"
        cat "$first_home/.ssh/authorized_keys"
        echo ""
        read -rp "Add another key? (y/N): " add_another
        if [[ ! "$add_another" =~ ^[Yy]$ ]]; then
            SSH_KEY=""
            return
        fi
    fi

    echo ""
    echo -e "${CYAN}How to generate an SSH key:${NC}"
    echo "  ssh-keygen -t ed25519 -C \"your_email@example.com\""
    echo "  cat ~/.ssh/id_ed25519.pub"
    echo ""
    echo "Paste your SSH public key (starts with 'ssh-rsa' or 'ssh-ed25519')."
    echo -e "${YELLOW}Press Enter on an empty line to SKIP.${NC}"
    echo ""

    SSH_KEY=""
    while IFS= read -r line; do
        [[ -z "$line" ]] && break
        SSH_KEY+="$line"
    done

    if [[ -z "$SSH_KEY" ]]; then
        warn "No SSH key provided. SSH hardening will be skipped."
        warn "You can add a key later: echo 'your-key' >> ~/.ssh/authorized_keys"
    elif [[ "$SSH_KEY" =~ ^ssh-(rsa|ed25519|ecdsa) ]]; then
        success "Valid SSH key format detected"
    else
        warn "Key format not recognized — proceeding anyway"
    fi
}

# ----------------------------------------------------------
# KEYBOARD / LOCALE PRESERVATION
# ----------------------------------------------------------
backup_keyboard_locale() {
    step "BACKING UP KEYBOARD LOCALE"

    if [[ -f /etc/default/keyboard ]]; then
        cp -f /etc/default/keyboard /etc/default/keyboard.debuntu.bak
        KEYBOARD_BACKED_UP=true
        success "Keyboard locale backed up"
        info "Current layout: $(grep -E '^XKBLAYOUT' /etc/default/keyboard || echo 'unknown')"
    else
        info "No keyboard configuration found to backup"
    fi

    if [[ -f /etc/default/console-setup ]]; then
        cp -f /etc/default/console-setup /etc/default/console-setup.debuntu.bak
    fi

    # Pre-seed debconf so dpkg won't prompt
    if command -v debconf-set-selections &>/dev/null && [[ -f /etc/default/keyboard ]]; then
        local layout
        layout=$(grep XKBLAYOUT /etc/default/keyboard 2>/dev/null | cut -d'"' -f2 || echo 'us')
        echo "keyboard-configuration keyboard-configuration/layoutcode string $layout" \
            | debconf-set-selections 2>/dev/null || true
    fi
}

restore_keyboard_locale() {
    if [[ -f /etc/default/keyboard.debuntu.bak ]]; then
        info "Restoring keyboard locale..."
        cp -f /etc/default/keyboard.debuntu.bak /etc/default/keyboard
        setupcon --force 2>/dev/null || true
        udevadm trigger --subsystem-match=input --action=change 2>/dev/null || true
        success "Keyboard locale restored"
    fi
    if [[ -f /etc/default/console-setup.debuntu.bak ]]; then
        cp -f /etc/default/console-setup.debuntu.bak /etc/default/console-setup
    fi
}

# Trap: always restore keyboard on exit
cleanup_on_exit() {
    local rc=$?
    if [[ "$KEYBOARD_BACKED_UP" == "true" ]]; then
        restore_keyboard_locale
    fi
    exit $rc
}
trap cleanup_on_exit EXIT

# ----------------------------------------------------------
# PROTECT DESKTOP / BOOT PACKAGES
# ----------------------------------------------------------
protect_desktop_packages() {
    step "PROTECTING DESKTOP & BOOT PACKAGES"

    local packages=(
        # GNOME core
        gnome-shell gdm3 gnome-session gnome-session-bin gnome-terminal
        gnome-control-center mutter gnome-settings-daemon nautilus
        gnome-desktop3-data
        # X.org
        xorg xserver-xorg xserver-xorg-core xserver-xorg-input-all
        xserver-xorg-video-all
        # Display managers
        lightdm
        # Desktop meta-packages
        ubuntu-desktop ubuntu-desktop-minimal gnome gnome-core
        task-gnome-desktop task-desktop
        # Keyboard / locale
        keyboard-configuration console-setup console-setup-linux xkb-data
        # Bootloader & kernel (mark manual — never hold)
        grub-pc grub-efi-amd64 grub-efi-amd64-signed grub-common
        grub2-common shim-signed
        initramfs-tools initramfs-tools-core linux-base
        systemd systemd-sysv dbus dbus-user-session efibootmgr
    )

    # Also mark installed kernel packages
    local kpkgs
    kpkgs=$(dpkg-query -W -f='${Package}\n' 2>/dev/null \
            | grep -E '^linux-(image|headers)-' || true)

    for pkg in "${packages[@]}" $kpkgs; do
        apt-mark manual "$pkg" >> "$LOG_FILE" 2>&1 || true
    done

    success "Desktop and boot-critical packages protected"
}

# ----------------------------------------------------------
# CLEANUP BLOATWARE
# ----------------------------------------------------------
cleanup_bloatware() {
    step "REMOVING BLOATWARE"

    local bloatware=(
        # Telemetry / reporting
        popularity-contest reportbug
        # GNOME games
        gnome-games aisleriot gnome-mines gnome-sudoku gnome-mahjongg
        gnome-robots gnome-tetravex gnome-nibbles gnome-taquin gnome-chess
        four-in-a-row five-or-more hitori iagno lightsoff quadrapassel
        swell-foop tali
        # Unnecessary apps
        cheese gnome-calendar gnome-contacts gnome-maps gnome-weather
        simple-scan snapshot yelp
        # Tiny vim (full vim installed later)
        vim-tiny
    )

    local removed=0
    for pkg in "${bloatware[@]}"; do
        if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q '^install ok installed$'; then
            info "Removing: $pkg"
            apt-get purge -y "$pkg" >> "$LOG_FILE" 2>&1 || true
            ((removed++)) || true
        fi
    done

    if [[ $removed -gt 0 ]]; then
        success "Removed $removed bloatware packages"

        # Safe autoremove: simulate first, skip if critical packages would go
        local sim_remove
        sim_remove=$(apt-get autoremove --simulate 2>/dev/null | grep '^Remv ' | awk '{print $2}' || true)
        local critical_pat="grub|linux-image|linux-headers|systemd|initramfs|gnome-shell|gdm3|xserver|mutter"

        if [[ -n "$sim_remove" ]] && echo "$sim_remove" | grep -qE "$critical_pat"; then
            warn "Skipping autoremove — would remove critical packages"
        elif [[ -n "$sim_remove" ]]; then
            apt-get autoremove -y >> "$LOG_FILE" 2>&1 || true
        fi
        apt-get clean >> "$LOG_FILE" 2>&1 || true
    else
        info "No bloatware found"
    fi
}

# ----------------------------------------------------------
# SAFE INSTALL HELPER
# ----------------------------------------------------------
safe_install() {
    local pkgs=("$@")
    local pkg_str="${pkgs[*]}"

    # Simulate — abort if it would remove anything
    local sim
    sim=$(apt-get install --simulate --no-install-recommends "${pkgs[@]}" 2>&1)

    if echo "$sim" | grep -q '^Remv'; then
        warn "Installing '$pkg_str' would remove packages — skipping"
        echo "$sim" | grep '^Remv' >> "$LOG_FILE"
        return 1
    fi

    if apt-get install -y --no-install-recommends --no-remove "${pkgs[@]}" >> "$LOG_FILE" 2>&1; then
        success "Installed: $pkg_str"
    else
        warn "Failed to install: $pkg_str"
        return 1
    fi
}

# ----------------------------------------------------------
# INSTALL ESSENTIALS (single apt-get update)
# ----------------------------------------------------------
install_essentials() {
    step "INSTALLING ESSENTIAL PACKAGES"

    # Stop unattended-upgrades to prevent lock conflicts
    systemctl stop unattended-upgrades 2>/dev/null || true
    dpkg --configure -a >> "$LOG_FILE" 2>&1 || true

    # === THE ONLY apt-get update in the entire script ===
    info "Updating package lists..."
    apt-get update >> "$LOG_FILE" 2>&1 || warn "apt-get update failed"

    # Critical tools
    safe_install curl || install_static_curl
    safe_install wget git unzip zip gzip tar

    # Editors & shell
    safe_install nano vim zsh

    # Security & networking
    safe_install ufw fail2ban openssh-server
    safe_install net-tools dnsutils dbus-x11 dconf-cli

    # Monitoring & build
    safe_install btop build-essential

    # Modern CLI tools (optional — failures are fine)
    safe_install fzf jq
    safe_install bat       || true
    safe_install lsd       || true
    safe_install ripgrep   || true
    safe_install fd-find   || true
    safe_install fastfetch || true

    # Dev tools
    safe_install python3 python3-pip python3-venv
    safe_install nodejs npm

    # Fonts subsystem
    safe_install fontconfig

    success "Essential packages installed"
}

# ----------------------------------------------------------
# STATIC CURL FALLBACK (no eval)
# ----------------------------------------------------------
install_static_curl() {
    warn "apt curl failed — attempting static binary install"
    local url="https://github.com/moparisthebest/static-curl/releases/latest/download/curl-amd64"

    if command -v python3 &>/dev/null; then
        python3 -c "import urllib.request; urllib.request.urlretrieve('$url', '/usr/local/bin/curl')"
    elif command -v wget &>/dev/null; then
        wget -qO /usr/local/bin/curl "$url"
    else
        error "No way to download static curl (python3/wget missing)"
        return 1
    fi

    chmod +x /usr/local/bin/curl
    hash -r 2>/dev/null || true
    success "Static curl installed to /usr/local/bin/curl"
}

# ----------------------------------------------------------
# FONT INSTALLATION
# ----------------------------------------------------------
install_fonts() {
    step "INSTALLING MARTIANMONO NERD FONT"

    local font_dest="/usr/local/share/fonts/NerdFonts"
    local font_url="https://github.com/ryanoasis/nerd-fonts/releases/latest/download/MartianMono.zip"
    local temp_zip="/tmp/MartianMono.zip"

    mkdir -p "$font_dest"

    info "Downloading MartianMono Nerd Font..."
    if ! curl -fsSL "$font_url" -o "$temp_zip"; then
        error "Failed to download fonts"
        return 1
    fi

    unzip -o "$temp_zip" -d "$font_dest" >> "$LOG_FILE" 2>&1
    rm -f "$temp_zip"
    success "MartianMono Nerd Font installed to $font_dest"

    # Fontconfig: set as default monospace
    mkdir -p /etc/fonts/conf.d
    cat << 'FONTCONF' > /etc/fonts/local.conf
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
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
FONTCONF

    fc-cache -fv >> "$LOG_FILE" 2>&1
    success "MartianMono set as system-wide default monospace font"
}

# ----------------------------------------------------------
# DCONF: GNOME DEFAULTS
# ----------------------------------------------------------
setup_dconf_defaults() {
    step "CONFIGURING SYSTEM-WIDE GNOME DEFAULTS"

    if ! command -v dconf &>/dev/null; then
        warn "dconf not available — skipping GNOME defaults"
        return
    fi

    mkdir -p /etc/dconf/profile /etc/dconf/db/local.d

    # User profile
    cat << 'DPROF' > /etc/dconf/profile/user
user-db:user
system-db:local
DPROF

    # Font & terminal settings
    cat << 'DCONF' > /etc/dconf/db/local.d/00-debuntu-fonts
[org/gnome/desktop/interface]
monospace-font-name='MartianMono Nerd Font 11'

[org/gnome/terminal/legacy/profiles:]
default='b1dcc9dd-5262-4d8d-a863-c897e6d979b9'
list=['b1dcc9dd-5262-4d8d-a863-c897e6d979b9']

[org/gnome/terminal/legacy/profiles:/:b1dcc9dd-5262-4d8d-a863-c897e6d979b9]
visible-name='Debuntu'
use-system-font=true
use-theme-colors=true
DCONF

    dconf update >> "$LOG_FILE" 2>&1 || warn "dconf update failed"
    success "System-wide GNOME defaults applied"
}

# ----------------------------------------------------------
# CONSOLE FONT (TTY)
# ----------------------------------------------------------
setup_console_font() {
    step "CONFIGURING CONSOLE FONT"

    if ! dpkg-query -W -f='${Status}' console-setup 2>/dev/null | grep -q '^install ok installed$'; then
        safe_install console-setup || return
    fi

    if [[ -f /etc/default/console-setup ]]; then
        sed -i 's/^FONTFACE=.*/FONTFACE="Terminus"/' /etc/default/console-setup
        sed -i 's/^FONTSIZE=.*/FONTSIZE="16x32"/'    /etc/default/console-setup
        setupcon --force >> "$LOG_FILE" 2>&1 || true
        success "Console font set to Terminus 16x32"
    else
        warn "console-setup config not found — skipping"
    fi
}

# ----------------------------------------------------------
# ZSH: OMZ + P10K + PLUGINS (for ALL users)
# ----------------------------------------------------------
setup_zsh() {
    step "CONFIGURING ZSH"

    for user_info in "${ALL_USERS[@]}"; do
        local username="${user_info%%:*}"
        local home="${user_info##*:}"

        info "Setting up ZSH for $username..."

        # --- Oh-My-Zsh ---
        if [[ ! -d "$home/.oh-my-zsh" ]]; then
            if [[ "$username" == "root" ]]; then
                git clone --depth=1 https://github.com/ohmyzsh/ohmyzsh.git "$home/.oh-my-zsh" >> "$LOG_FILE" 2>&1 || {
                    warn "OMZ install failed for $username"; continue
                }
            else
                sudo -u "$username" git clone --depth=1 https://github.com/ohmyzsh/ohmyzsh.git "$home/.oh-my-zsh" 2>&1 | tee -a "$LOG_FILE" >/dev/null || {
                    warn "OMZ install failed for $username"; continue
                }
            fi
        fi

        # --- Powerlevel10k ---
        local p10k_dir="$home/.oh-my-zsh/custom/themes/powerlevel10k"
        if [[ ! -d "$p10k_dir" ]]; then
            if [[ "$username" == "root" ]]; then
                git clone --depth=1 https://github.com/romkatv/powerlevel10k.git "$p10k_dir" >> "$LOG_FILE" 2>&1 || true
            else
                sudo -u "$username" git clone --depth=1 https://github.com/romkatv/powerlevel10k.git "$p10k_dir" 2>&1 | tee -a "$LOG_FILE" >/dev/null || true
            fi
        fi

        # --- Plugins ---
        local plugins_dir="$home/.oh-my-zsh/custom/plugins"
        mkdir -p "$plugins_dir"
        local clone_cmd="git"
        [[ "$username" != "root" ]] && clone_cmd="sudo -u $username git"

        if [[ ! -d "$plugins_dir/zsh-autosuggestions" ]]; then
            $clone_cmd clone --depth=1 https://github.com/zsh-users/zsh-autosuggestions "$plugins_dir/zsh-autosuggestions" >> "$LOG_FILE" 2>&1 || true
        fi
        if [[ ! -d "$plugins_dir/zsh-syntax-highlighting" ]]; then
            $clone_cmd clone --depth=1 https://github.com/zsh-users/zsh-syntax-highlighting.git "$plugins_dir/zsh-syntax-highlighting" >> "$LOG_FILE" 2>&1 || true
        fi

        # Fix ownership for root-created dirs
        chown -R "$username:$(id -gn "$username")" "$home/.oh-my-zsh" 2>/dev/null || true

        # --- Deploy config files ---
        for dotfile in .zshrc .zshrc_aliases .p10k.zsh; do
            if [[ -f "$REPO_ROOT/config/$dotfile" ]]; then
                cp "$REPO_ROOT/config/$dotfile" "$home/$dotfile"
                chown "$username:$(id -gn "$username")" "$home/$dotfile" 2>/dev/null || true
            fi
        done

        # --- Set ZSH as default shell ---
        local zsh_path
        zsh_path="$(command -v zsh)"
        if [[ -n "$zsh_path" ]]; then
            chsh -s "$zsh_path" "$username" 2>/dev/null || true
        fi
    done

    success "ZSH configured for all users"
}

# ----------------------------------------------------------
# NANO CONFIG
# ----------------------------------------------------------
setup_nano() {
    step "CONFIGURING NANO"

    for user_info in "${ALL_USERS[@]}"; do
        local username="${user_info%%:*}"
        local home="${user_info##*:}"
        if [[ -f "$REPO_ROOT/config/.nanorc" ]]; then
            cp "$REPO_ROOT/config/.nanorc" "$home/.nanorc"
            chown "$username:$(id -gn "$username")" "$home/.nanorc" 2>/dev/null || true
        fi
    done

    success "Nano configured for all users"
}

# ----------------------------------------------------------
# FASTFETCH CONFIG
# ----------------------------------------------------------
setup_fastfetch() {
    step "CONFIGURING FASTFETCH"

    local config_src="$REPO_ROOT/config/fastfetch"
    if [[ ! -d "$config_src" ]]; then
        warn "Fastfetch config directory not found — skipping"
        return
    fi

    for user_info in "${ALL_USERS[@]}"; do
        local username="${user_info%%:*}"
        local home="${user_info##*:}"
        local dest="$home/.config/fastfetch"
        mkdir -p "$dest"
        cp -r "$config_src/"* "$dest/"
        chown -R "$username:$(id -gn "$username")" "$dest" 2>/dev/null || true
    done

    success "Fastfetch configured for all users"
}

# ----------------------------------------------------------
# UFW FIREWALL
# ----------------------------------------------------------
setup_ufw() {
    step "CONFIGURING UFW FIREWALL"

    if ! command -v ufw &>/dev/null; then
        warn "UFW not installed — skipping"
        return
    fi

    # Warn before reset if existing rules are present
    local rule_count
    rule_count=$(ufw status 2>/dev/null | grep -cE '^\[' || echo 0)
    if [[ "$rule_count" -gt 0 ]]; then
        warn "UFW has $rule_count existing rule(s) — resetting to defaults"
    fi

    {
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow ssh comment 'SSH'
        ufw --force enable
    } >> "$LOG_FILE" 2>&1

    success "UFW configured: deny incoming, allow SSH"
    ufw status verbose
}

# ----------------------------------------------------------
# FAIL2BAN
# ----------------------------------------------------------
setup_fail2ban() {
    step "CONFIGURING FAIL2BAN"

    if ! command -v fail2ban-client &>/dev/null; then
        warn "fail2ban not installed — skipping"
        return
    fi

    cat << 'F2B' > /etc/fail2ban/jail.local
# Debuntu Provisioning - fail2ban config
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
banaction = ufw

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 24h
F2B

    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    systemctl restart fail2ban >> "$LOG_FILE" 2>&1
    success "fail2ban configured for SSH protection"
}

# ----------------------------------------------------------
# SSH: KEY DEPLOYMENT + CONDITIONAL HARDENING
# ----------------------------------------------------------
setup_ssh() {
    step "SSH CONFIGURATION"

    # --- Deploy key if provided ---
    if [[ -n "$SSH_KEY" ]]; then
        for user_info in "${ALL_USERS[@]}"; do
            local username="${user_info%%:*}"
            local home="${user_info##*:}"
            [[ "$username" == "root" ]] && continue   # no root SSH

            local ssh_dir="$home/.ssh"
            local auth_keys="$ssh_dir/authorized_keys"

            mkdir -p "$ssh_dir"
            chmod 700 "$ssh_dir"

            # Duplicate check before appending
            if [[ -f "$auth_keys" ]] && grep -qF "$SSH_KEY" "$auth_keys"; then
                info "Key already present for $username — skipping"
            else
                echo "$SSH_KEY" >> "$auth_keys"
                success "SSH key added for $username"
            fi

            chmod 600 "$auth_keys"
            chown -R "$username:$(id -gn "$username")" "$ssh_dir"
        done
    else
        info "No SSH key provided — skipping key deployment"
    fi

    # --- Conditional hardening ---
    # Only harden if at least one user has an authorized key
    local has_key=false
    for user_info in "${ALL_USERS[@]}"; do
        local home="${user_info##*:}"
        if [[ -f "$home/.ssh/authorized_keys" && -s "$home/.ssh/authorized_keys" ]]; then
            has_key=true
            break
        fi
    done

    if ! $has_key; then
        warn "No SSH keys found for any user — skipping SSH hardening to prevent lockout"
        return
    fi

    harden_sshd
}

harden_sshd() {
    local backup_dir
    backup_dir="/etc/ssh/backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    cp -p /etc/ssh/sshd_config "$backup_dir/" 2>/dev/null || true
    cp -rp /etc/ssh/sshd_config.d "$backup_dir/" 2>/dev/null || true
    info "sshd_config backed up to $backup_dir"

    local ssh_port="${SSH_PORT:-22}"

    # Include MUST come before any settings to avoid parse issues
    cat << EOF > /etc/ssh/sshd_config
# ============================================================
# DEBUNTU HARDENED SSH CONFIG — generated $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

# Include drop-in configs FIRST (before any settings)
Include /etc/ssh/sshd_config.d/*.conf

# Network
Port $ssh_port
Protocol 2
AddressFamily inet

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM yes
MaxAuthTries 3
MaxSessions 3

# Session
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Security
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no

# Banner
Banner /etc/ssh/banner

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# SFTP
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

    # Modern crypto
    mkdir -p /etc/ssh/sshd_config.d
    cat << 'CRYPTO' > /etc/ssh/sshd_config.d/ciphers.conf
# Post-Quantum Ready Cryptographic Algorithms
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
CRYPTO

    # Login banner
    cat << 'SSHBANNER' > /etc/ssh/banner
========================================================
              AUTHORIZED ACCESS ONLY
  All connections are monitored and logged.
  Unauthorized access attempts will be prosecuted.
========================================================
SSHBANNER

    # Prefer ssh.service over ssh.socket
    systemctl stop ssh.socket 2>/dev/null || true
    systemctl disable ssh.socket 2>/dev/null || true
    systemctl mask ssh.socket 2>/dev/null || true

    if sshd -t 2>/dev/null; then
        success "SSH configuration valid"
        systemctl enable ssh.service  2>/dev/null || systemctl enable sshd.service  2>/dev/null
        systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service 2>/dev/null
        success "SSH daemon restarted with hardened config"
    else
        error "SSH config validation failed — restoring backup"
        cp "$backup_dir/sshd_config" /etc/ssh/sshd_config
        return 1
    fi
}

# ----------------------------------------------------------
# SUMMARY
# ----------------------------------------------------------
show_summary() {
    echo ""
    echo -e "${GREEN}${BOLD}"
    echo "========================================================"
    echo "           PROVISIONING COMPLETE!"
    echo "========================================================"
    echo -e "${NC}"
    echo ""
    echo -e "${BOLD}What was done:${NC}"
    echo "  - Bloatware removed"
    echo "  - MartianMono Nerd Font installed (system-wide)"
    echo "  - ZSH + Oh-My-Zsh + Powerlevel10k for all users"
    echo "  - Fastfetch configured"
    echo "  - UFW firewall enabled (SSH allowed)"
    if [[ -n "$SSH_KEY" ]]; then
        echo "  - SSH key deployed + daemon hardened"
    else
        echo "  - SSH hardening skipped (no key provided)"
    fi
    echo ""
    echo -e "${YELLOW}Log file:${NC} $LOG_FILE"
    echo ""
    echo -e "${BOLD}Next steps:${NC}"
    echo "  1. Log out and back in to activate ZSH"
    echo "  2. Run 'p10k configure' to customize your prompt"
    echo ""

    if [[ -z "$SSH_KEY" ]]; then
        echo -e "${YELLOW}NOTE: No SSH key was added. Add one later and re-run to harden SSH:${NC}"
        echo "  echo 'your-key' >> ~/.ssh/authorized_keys"
        echo ""
    fi
}

# ============================================================
# MAIN
# ============================================================
main() {
    mkdir -p "$(dirname "$LOG_FILE")"
    {
        echo "=== DEBUNTU PROVISIONING LOG ==="
        echo "Started: $(date)"
        echo "Version: $SCRIPT_VERSION"
        echo ""
    } > "$LOG_FILE"

    show_banner
    preflight_checks
    get_users                    # populate ALL_USERS (once)
    ensure_repo                  # auto-clone if standalone
    prompt_ssh_key               # interactive SSH key input

    backup_keyboard_locale
    protect_desktop_packages
    cleanup_bloatware
    install_essentials           # single apt-get update here
    install_fonts
    setup_dconf_defaults
    setup_console_font
    setup_zsh                    # OMZ + p10k + plugins for ALL users
    setup_nano
    setup_fastfetch
    setup_ufw
    setup_fail2ban
    setup_ssh                    # key deploy + conditional hardening

    restore_keyboard_locale

    echo ""                     >> "$LOG_FILE"
    echo "Completed: $(date)"   >> "$LOG_FILE"

    show_summary
}

main "$@"
