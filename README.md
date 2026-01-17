# Debuntu Provisioning Suite

> Production-ready, idempotent provisioning for **Ubuntu LTS** and **Debian Stable** virtual machines.

[![Bash](https://img.shields.io/badge/Bash-5.0+-green.svg)](https://www.gnu.org/software/bash/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%20|%2024.04-orange.svg)](https://ubuntu.com/)
[![Debian](https://img.shields.io/badge/Debian-11%20|%2012-red.svg)](https://www.debian.org/)

---

## ✨ Features

- 🧹 **System Cleanup** - Removes bloatware and unnecessary packages
- 👤 **User Management** - Configures sudo and permissions
- 🔤 **MartianMono Nerd Font** - Installed system-wide as default monospace
- 🐚 **ZSH + Oh-My-Zsh** - With Powerlevel10k theme and useful plugins
- ⌨️ **LazyVim** - Full Neovim IDE experience for all users
- 🖥️ **Fastfetch** - Beautiful system info with image protocol support
- 🔒 **SSH Hardening** - Key-based auth, modern cryptography
- 🛡️ **UFW + fail2ban** - Firewall and intrusion prevention

---

## 📁 Directory Structure

```
Debuntu_provisionning/
├── config/
│   ├── fastfetch/
│   │   └── config.jsonc       # Fastfetch config (kitty/sixel support)
│   ├── .nanorc                # Nano editor config with syntax highlighting
│   ├── .zshrc                 # ZSH config with Oh-My-Zsh + Powerlevel10k
│   └── .zshrc_aliases         # Custom command aliases
├── fonts/
│   └── MartianMono_/          # MartianMono Nerd Font files
├── scripts/
│   └── setup.sh               # 🚀 Main provisioning script (includes SSH hardening)
└── README.md                  # This file
```

---

## 🚀 Quick Start

### One-liner Installation

```bash
git clone https://github.com/Likkyh/Debuntu_provisionning.git
cd Debuntu_provisionning
sudo ./scripts/setup.sh
```

### Step-by-Step

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Likkyh/Debuntu_provisionning.git
   cd Debuntu_provisionning
   ```

2. **Make the script executable:**
   ```bash
   chmod +x scripts/setup.sh
   ```

3. **Run with sudo:**
   ```bash
   sudo ./scripts/setup.sh
   ```

4. **Follow the prompts:**
   - The script will ask for your SSH public key
   - All steps are logged to `/var/log/debuntu-setup.log`

5. **Log out and back in** to activate ZSH

---

## 📦 Packages Installed

### Core Utilities
| Package | Description |
|---------|-------------|
| `curl`, `wget` | HTTP clients |
| `git` | Version control |
| `unzip`, `zip`, `tar` | Archive tools |

### Modern CLI Tools
| Package | Replaces | Description |
|---------|----------|-------------|
| `bat` | `cat` | Syntax highlighting |
| `lsd` | `ls` | Modern ls with icons |
| `fd-find` | `find` | Fast file finder |
| `ripgrep` | `grep` | Fast regex search |
| `fzf` | - | Fuzzy finder |
| `btop` | `top`/`htop` | Resource monitor |

### Development
| Package | Description |
|---------|-------------|
| `neovim` | Modern Vim (LazyVim base) |
| `nodejs`, `npm` | JavaScript runtime |
| `python3`, `pip` | Python 3 |

### Security
| Package | Description |
|---------|-------------|
| `ufw` | Firewall |
| `fail2ban` | Intrusion prevention |
| `openssh-server` | SSH daemon |

---

## 🗑️ Packages Removed

The following bloatware packages are removed if present:

| Package | Reason |
|---------|--------|
| `vim-tiny` | Replaced by full `vim` + LazyVim |
| `popularity-contest` | Telemetry |
| `reportbug` | Debian bug reporting |
| GNOME Games | All games removed |
| `cheese` | Webcam app |

> **Note:** `nano` is preserved as requested.

---

## 🔧 Configuration Details

### ZSH Configuration

The `.zshrc` automatically installs:
- **Oh-My-Zsh** - ZSH framework
- **Powerlevel10k** - Fast, customizable prompt
- **zsh-autosuggestions** - Fish-like suggestions
- **zsh-syntax-highlighting** - Command highlighting

**Customize your prompt:**
```bash
p10k configure
```

### Aliases (`.zshrc_aliases`)

| Alias | Command | Description |
|-------|---------|-------------|
| `ls` | `lsd --group-directories-first` | Modern ls |
| `ll` | `lsd -lAh ...` | Long listing |
| `cat` | `bat --paging=never` | With syntax highlighting |
| `update` | `sudo apt update && upgrade -y` | System update |
| `v` | `nvim` | Open Neovim |

### Fastfetch

Displays system information on terminal open with:
- Image protocol support (kitty/sixel)
- Hardware, software, network, and time sections
- Auto-detects distro logo

---

## 🔒 Security Configuration

### UFW Firewall
```bash
Default: deny incoming, allow outgoing
Allowed: SSH (port 22)
```

**Manage rules:**
```bash
sudo ufw status           # View status
sudo ufw allow 80/tcp     # Allow HTTP
sudo ufw delete allow 80  # Remove rule
```

### fail2ban

Configured to protect SSH:
- **Max retries:** 3
- **Ban time:** 24 hours
- **Find time:** 10 minutes

**Check status:**
```bash
sudo fail2ban-client status sshd
```

### SSH Hardening

The SSH daemon is hardened with:
- Root login disabled
- Password authentication disabled
- Public key authentication only
- Modern cryptographic algorithms (post-quantum ready)
- Login banner enabled

> SSH hardening is automatically performed by `setup.sh`. The script will guide you through adding your SSH public key before disabling password authentication.

---

## 📋 Post-Installation Checklist

- [ ] Log out and back in to activate ZSH
- [ ] Run `p10k configure` to customize prompt
- [ ] Open `nvim` to let LazyVim install plugins
- [ ] Verify SSH key login works before closing session
- [ ] Review UFW rules: `sudo ufw status`
- [ ] Delete this checklist once verified ✓

---

## 📝 Log File

All operations are logged to:
```
/var/log/debuntu-setup.log
```

View the log:
```bash
cat /var/log/debuntu-setup.log
```

---

## 🛠️ Troubleshooting

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
If you're locked out, use console access to:
```bash
sudo nano /etc/ssh/sshd_config
# Set PasswordAuthentication yes
sudo systemctl restart ssh
```

### Fastfetch not running
```bash
# Check if installed
which fastfetch

# Install manually
sudo apt install fastfetch
```

---

## 📄 License

MIT License - Feel free to use and modify.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

**Made with ❤️ for the sysadmin community**
