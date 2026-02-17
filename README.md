# Debuntu Provisioning Suite

> Production-ready, idempotent provisioning for **Ubuntu LTS** and **Debian Stable** virtual machines.

[![Bash](https://img.shields.io/badge/Bash-5.0+-green.svg)](https://www.gnu.org/software/bash/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%20|%2024.04-orange.svg)](https://ubuntu.com/)
[![Debian](https://img.shields.io/badge/Debian-11%20|%2012-red.svg)](https://www.debian.org/)

---

## Features

- **System Cleanup** — Removes bloatware, games, and telemetry packages
- **MartianMono Nerd Font** — Installed system-wide as the default monospace font
- **ZSH + Oh-My-Zsh + Powerlevel10k** — Pre-installed for all users (including root)
- **Fastfetch** — System info on terminal open
- **SSH Hardening** — Key-based auth with modern crypto (conditional — skipped if no key provided)
- **UFW + fail2ban** — Firewall and SSH intrusion prevention
- **Idempotent** — Safe to run multiple times

---

## Directory Structure

```
Debuntu_provisionning/
├── config/
│   ├── fastfetch/
│   │   └── config.jsonc       # Fastfetch config
│   ├── .nanorc                # Nano editor config
│   ├── .p10k.zsh             # Powerlevel10k prompt config
│   ├── .zshrc                # ZSH config (Oh-My-Zsh + Powerlevel10k)
│   └── .zshrc_aliases        # Custom command aliases
├── scripts/
│   └── setup.sh              # Main provisioning script
└── README.md
```

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

The script will auto-clone the repository to get configuration files.

### What happens

1. The script asks for your **SSH public key** (press Enter to skip)
2. Bloatware is removed, essential packages are installed
3. ZSH, fonts, configs are deployed for **all users** (UID >= 1000 + root)
4. UFW and fail2ban are configured
5. SSH is hardened **only if** an SSH key is present (prevents lockout)
6. Everything is logged to `/var/log/debuntu-setup.log`

---

## Packages

### Installed

| Category | Packages |
|----------|----------|
| Core | `curl`, `wget`, `git`, `unzip`, `zip`, `tar` |
| Editors | `nano`, `vim`, `zsh` |
| Modern CLI | `bat`, `lsd`, `fd-find`, `ripgrep`, `fzf`, `btop`, `fastfetch` |
| Dev | `python3`, `pip`, `nodejs`, `npm`, `build-essential` |
| Security | `ufw`, `fail2ban`, `openssh-server` |
| Fonts | `fontconfig`, MartianMono Nerd Font |

### Removed

| Package | Reason |
|---------|--------|
| `vim-tiny` | Replaced by full `vim` |
| `popularity-contest` | Telemetry |
| `reportbug` | Unnecessary on provisioned VMs |
| GNOME games | All games (aisleriot, mines, sudoku, etc.) |
| `cheese`, `gnome-calendar`, `gnome-contacts`, `gnome-maps`, `gnome-weather`, `simple-scan`, `yelp` | Unnecessary apps |

---

## Configuration

### ZSH

Oh-My-Zsh, Powerlevel10k, and plugins are **pre-installed by the script** — the `.zshrc` does not auto-install anything at shell startup.

Plugins enabled: `git`, `sudo`, `command-not-found`, `zsh-autosuggestions`, `zsh-syntax-highlighting`, `colored-man-pages`, `extract`

Customize your prompt:
```bash
p10k configure
```

### Aliases (`.zshrc_aliases`)

| Alias | Command | Description |
|-------|---------|-------------|
| `ls` | `lsd --group-directories-first` | Modern ls with icons |
| `ll` | `lsd -lAh ...` | Long listing |
| `cat` | `bat --paging=never` | Syntax highlighted cat |
| `update` | `sudo apt update && upgrade -y` | System update |
| `v` / `vi` / `vim` | `nvim` | Neovim |
| `top` / `htop` | `btop` | Resource monitor |

### Fastfetch

Runs on every interactive shell open (configured in `.zshrc`). Config lives at `~/.config/fastfetch/config.jsonc`.

---

## Security

### UFW Firewall

```
Default: deny incoming, allow outgoing
Allowed: SSH (port 22)
```

```bash
sudo ufw status           # View status
sudo ufw allow 80/tcp     # Allow HTTP
sudo ufw delete allow 80  # Remove rule
```

### fail2ban

SSH jail configured:
- **Max retries:** 3
- **Ban time:** 24 hours
- **Find time:** 10 minutes

```bash
sudo fail2ban-client status sshd
```

### SSH Hardening

Applied **only when an SSH key is present** (prevents lockout):
- Root login disabled
- Password authentication disabled
- Public key authentication only
- Modern cryptographic algorithms (post-quantum ready)
- `Include` directive placed before all settings (correct sshd_config ordering)

If no SSH key is provided during setup, you can add one later and re-run the script:
```bash
echo 'your-public-key' >> ~/.ssh/authorized_keys
sudo bash scripts/setup.sh
```

---

## Post-Installation

1. Log out and back in to activate ZSH
2. Run `p10k configure` to customize your prompt
3. Verify SSH key login works before closing your session
4. Review UFW rules: `sudo ufw status`

---

## Troubleshooting

### ZSH not default shell
```bash
chsh -s $(which zsh)
# Log out and back in
```

### Fonts not displaying correctly
```bash
fc-cache -fv
# Restart terminal
```

### SSH locked out
Use console/VNC access:
```bash
sudo nano /etc/ssh/sshd_config
# Set: PasswordAuthentication yes
sudo systemctl restart ssh
```

---

## Log File

All operations are logged to `/var/log/debuntu-setup.log`.

---

## License

MIT License
