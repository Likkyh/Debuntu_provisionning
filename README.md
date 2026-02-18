# Debuntu Provisioning Suite

> Idempotent provisioning script for **Ubuntu LTS** and **Debian Stable** virtual machines.
> One command to go from a fresh install to a fully configured, secured, and modern development environment.

[![Bash](https://img.shields.io/badge/Bash-5.0+-green.svg)](https://www.gnu.org/software/bash/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%20|%2024.04-orange.svg)](https://ubuntu.com/)
[![Debian](https://img.shields.io/badge/Debian-11%20|%2012-red.svg)](https://www.debian.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Features

- **System cleanup** — Removes bloatware, games, and telemetry packages
- **Modern CLI tools** — `bat`, `lsd`, `ripgrep`, `fd`, `fzf`, `btop`, `fastfetch`
- **ZSH + Oh-My-Zsh + Powerlevel10k** — Pre-configured for all users (including root)
- **MartianMono Nerd Font** — Installed system-wide as the default monospace font
- **SSH hardening** — Key-based auth with post-quantum crypto (conditional — skipped if no key provided)
- **UFW + fail2ban** — Firewall and SSH intrusion prevention
- **Fastfetch** — System info displayed on every terminal open
- **Nano configuration** — Syntax highlighting, line numbers, modern editing defaults
- **150+ shell aliases** — Safety wrappers, APT/git/systemctl shortcuts, modern tool replacements
- **Idempotent** — Safe to run multiple times without side effects

---

## Quick Start

### Option 1: Clone and run

```bash
git clone https://github.com/Likkyh/Debuntu_provisionning.git
cd Debuntu_provisionning
sudo bash scripts/setup.sh
```

### Option 2: curl | bash (self-bootstrapping)

```bash
curl -fsSL https://raw.githubusercontent.com/Likkyh/Debuntu_provisionning/main/scripts/setup.sh | sudo bash
```

The script auto-clones the repository to get configuration files.

### What happens

1. Detects your OS and validates compatibility (Ubuntu LTS / Debian Stable only)
2. Asks for your **SSH public key** (press Enter to skip — detects existing keys)
3. Backs up your keyboard layout (restored on exit)
4. Removes bloatware, installs essential packages
5. Installs MartianMono Nerd Font and configures GNOME Terminal
6. Deploys ZSH, Oh-My-Zsh, Powerlevel10k, and plugins for **all users** (UID >= 1000 + root)
7. Configures nano, fastfetch, and shell aliases
8. Sets up UFW firewall and fail2ban
9. Hardens SSH **only if** an SSH key is present (prevents lockout)
10. Everything is logged to `/var/log/debuntu-setup.log`

---

## Requirements

| Requirement | Details |
|---|---|
| **OS** | Ubuntu LTS (22.04, 24.04) or Debian Stable (11, 12) |
| **Privileges** | Root / sudo |
| **Network** | Internet access (downloads packages, fonts, ZSH plugins) |
| **Shell** | Bash 5.0+ |

---

## Packages

### Installed

| Category | Packages |
|---|---|
| **Core tools** | `curl`, `wget`, `git`, `unzip`, `zip`, `gzip`, `tar` |
| **Editors** | `nano`, `vim`, `zsh` |
| **Modern CLI** | `bat`, `lsd`, `fd-find`, `ripgrep`, `fzf`, `btop`, `fastfetch` |
| **Dev tools** | `build-essential`, `python3`, `python3-pip`, `python3-venv`, `nodejs`, `npm`, `jq` |
| **Security** | `ufw`, `fail2ban`, `openssh-server` |
| **System** | `fontconfig`, `net-tools`, `dnsutils`, `dbus-x11`, `dconf-cli`, `console-setup` |
| **Fonts** | MartianMono Nerd Font (system-wide), Terminus (TTY console) |
| **ZSH plugins** | zsh-autosuggestions, zsh-syntax-highlighting |

### Removed

| Package | Reason |
|---|---|
| `vim-tiny` | Replaced by full `vim` |
| `popularity-contest` | Telemetry |
| `reportbug` | Unnecessary on provisioned VMs |
| GNOME games | `aisleriot`, `gnome-mines`, `gnome-sudoku`, `gnome-mahjongg`, `gnome-chess`, `gnome-robots`, `gnome-tetravex`, `gnome-nibbles`, `gnome-taquin`, `four-in-a-row`, `five-or-more`, `hitori`, `iagno`, `lightsoff`, `quadrapassel`, `swell-foop`, `tali` |
| Unnecessary apps | `cheese`, `gnome-calendar`, `gnome-contacts`, `gnome-maps`, `gnome-weather`, `simple-scan`, `snapshot`, `yelp` |

### Protected (never removed)

GNOME shell, GDM, Mutter, Nautilus, X.org, systemd, kernel, bootloader, initramfs, firmware, keyboard/locale packages — the script simulates removals before executing and aborts if any critical package would be affected.

---

## Configuration

### ZSH

Oh-My-Zsh, Powerlevel10k, and all plugins are **installed by the script** — nothing is downloaded at shell startup.

**Plugins:** `git`, `sudo`, `command-not-found`, `zsh-autosuggestions`, `zsh-syntax-highlighting`, `colored-man-pages`, `extract`

**History:** 50,000 entries, deduplicated, timestamped, shared between terminals.

Customize the prompt anytime:
```bash
p10k configure
```

### Shell Aliases

The full alias file is at `config/.zshrc_aliases`. Highlights:

| Alias | Replacement | Description |
|---|---|---|
| `cat` | `bat --paging=never` | Syntax-highlighted output |
| `ls` | `lsd --group-directories-first` | Modern ls with icons |
| `ll` | `lsd -lAh` | Detailed listing |
| `lt` / `tree` | `lsd --tree` | Tree view |
| `top` / `htop` | `btop` | Modern resource monitor |
| `v` / `vi` / `vim` | `nvim` | Neovim |
| `cp` / `mv` / `rm` | `cp -iv` / `mv -iv` / `rm -Iv` | Confirm before overwrite/delete |

**APT shortcuts:**

| Alias | Command |
|---|---|
| `update` | `sudo apt update && sudo apt upgrade -y` |
| `install` | `sudo apt install` |
| `remove` | `sudo apt remove` |
| `search` | `apt search` |

**Git shortcuts:**

| Alias | Command |
|---|---|
| `gs` | `git status` |
| `ga` | `git add` |
| `gc` | `git commit -m` |
| `gp` | `git push` |
| `gl` | `git pull` |
| `gd` | `git diff` |
| `glog` | `git log --oneline --graph --decorate -10` |

**Systemctl shortcuts:**

| Alias | Command |
|---|---|
| `scstart` | `sudo systemctl start` |
| `scstop` | `sudo systemctl stop` |
| `screstart` | `sudo systemctl restart` |
| `scstatus` | `sudo systemctl status` |
| `scenable` | `sudo systemctl enable` |

**Navigation:**

| Alias | Target |
|---|---|
| `..` / `...` / `....` | Parent directories |
| `config` | `~/.config` |
| `docs` | `~/Documents` |
| `dl` | `~/Downloads` |

**Utility functions:**

| Function | Description |
|---|---|
| `mkcd <dir>` | Create directory and cd into it |
| `backup <file>` | Create a timestamped backup copy |
| `extract <archive>` | Universal extractor (tar, zip, 7z, rar, etc.) |
| `ducks` | Show top 15 disk-consuming directories |

### Nano

Line numbers, 4-space tabs (spaces, not tabs), auto-indent, soft wrapping, mouse support, syntax highlighting, custom color scheme. Config at `config/.nanorc`.

### Fastfetch

Runs on every interactive shell session. Displays system info in four color-coded sections:

- **Hardware** (green): host, CPU, GPU, display, RAM, disk, battery
- **Software** (yellow): OS, kernel, packages, shell
- **Network** (cyan): interface, IPv4, public IP, IPv6, MAC, link speed, SSID
- **System** (magenta): install age, uptime, date

Config at `config/fastfetch/config.jsonc`.

---

## Security

### UFW Firewall

```
Default: deny incoming, allow outgoing
Allowed: SSH (port 22)
```

```bash
sudo ufw status           # View rules
sudo ufw allow 80/tcp     # Allow HTTP
sudo ufw delete allow 80  # Remove rule
```

### fail2ban

SSH jail configuration:

| Setting | Value |
|---|---|
| Max retries | 3 |
| Ban time | 24 hours |
| Find time | 10 minutes |
| Ban action | UFW integration |

```bash
sudo fail2ban-client status sshd   # View banned IPs
```

### SSH Hardening

Applied **only when an SSH key is present** to prevent lockout.

**Authentication:**
- Root login: disabled
- Password authentication: disabled
- Public key authentication: enabled
- Max auth tries: 3
- Max sessions: 3

**Hardened settings:**
- X11 / agent / TCP forwarding: disabled
- Tunneling: disabled
- Login grace time: 30 seconds
- Client keepalive: every 5 minutes

**Post-quantum cipher suite:**
- Key exchange: `sntrup761x25519-sha512`, `curve25519-sha256`
- Ciphers: `chacha20-poly1305`, `aes256-gcm`, `aes128-gcm`
- MACs: `hmac-sha2-512-etm`, `hmac-sha2-256-etm`, `umac-128-etm`
- Host keys: `ssh-ed25519`, `rsa-sha2-512`

**Safety:** Original `sshd_config` is backed up before changes. Config is validated before restarting SSH — automatic rollback on validation failure.

To add SSH keys after installation and re-apply hardening:
```bash
echo 'your-public-key' >> ~/.ssh/authorized_keys
sudo bash scripts/setup.sh
```

---

## Project Structure

```
Debuntu_provisionning/
├── scripts/
│   └── setup.sh                # Main provisioning script
├── config/
│   ├── .zshrc                  # ZSH configuration (Oh-My-Zsh + P10K)
│   ├── .zshrc_aliases          # 150+ shell aliases and functions
│   ├── .p10k.zsh              # Powerlevel10k prompt config (lean style)
│   ├── .nanorc                # Nano editor config
│   └── fastfetch/
│       └── config.jsonc       # Fastfetch system info display
└── README.md
```

---

## Logging

All operations are logged to `/var/log/debuntu-setup.log` with timestamps and severity levels.

```bash
cat /var/log/debuntu-setup.log          # Full log
grep -E 'WARN|ERR' /var/log/debuntu-setup.log  # Warnings and errors only
```

---

## Post-Installation

1. **Log out and back in** to activate ZSH as your default shell
2. Run `p10k configure` to customize the prompt style
3. **Verify SSH key login works** before closing your current session
4. Check firewall rules: `sudo ufw status`
5. Review the log: `cat /var/log/debuntu-setup.log`

---

## Troubleshooting

### ZSH not set as default shell

```bash
chsh -s $(which zsh)
# Log out and back in
```

### Nerd Font icons not displaying

```bash
fc-cache -fv
# Restart your terminal emulator
```

### Locked out of SSH

Use console/VNC access:
```bash
sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

### Script failed mid-run

The script is idempotent — just run it again:
```bash
sudo bash scripts/setup.sh
```

Check the log for details:
```bash
cat /var/log/debuntu-setup.log
```

---

## License

MIT License
