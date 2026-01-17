# ============================================================
# DEBUNTU ZSH CONFIG - ~/.zshrc
# Optimized for Debian/Ubuntu with Oh-My-Zsh + Powerlevel10k
# ============================================================

# ----------------------------------------------------------
# OH-MY-ZSH INSTALLATION CHECK
# Automatically installs Oh-My-Zsh if not present
# ----------------------------------------------------------
export ZSH="$HOME/.oh-my-zsh"

# Install Oh-My-Zsh if not already installed
if [[ ! -d "$ZSH" ]]; then
    echo "Installing Oh-My-Zsh..."
    sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
fi

# ----------------------------------------------------------
# POWERLEVEL10K THEME
# ----------------------------------------------------------
# Check if Powerlevel10k is installed, install if missing
if [[ ! -d "${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k" ]]; then
    echo "Installing Powerlevel10k theme..."
    git clone --depth=1 https://github.com/romkatv/powerlevel10k.git "${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k" 2>/dev/null
fi

ZSH_THEME="powerlevel10k/powerlevel10k"

# Enable Powerlevel10k instant prompt (must be near top of .zshrc)
if [[ -r "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh" ]]; then
    source "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh"
fi

# ----------------------------------------------------------
# OH-MY-ZSH PLUGINS
# ----------------------------------------------------------
# Install zsh-autosuggestions if not present
if [[ ! -d "${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/plugins/zsh-autosuggestions" ]]; then
    echo "Installing zsh-autosuggestions..."
    git clone https://github.com/zsh-users/zsh-autosuggestions "${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/plugins/zsh-autosuggestions" 2>/dev/null
fi

# Install zsh-syntax-highlighting if not present
if [[ ! -d "${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting" ]]; then
    echo "Installing zsh-syntax-highlighting..."
    git clone https://github.com/zsh-users/zsh-syntax-highlighting.git "${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting" 2>/dev/null
fi

plugins=(
    git                     # Git aliases and functions
    sudo                    # Press ESC twice to prepend sudo
    command-not-found       # Suggests packages for unknown commands
    zsh-autosuggestions     # Fish-like autosuggestions
    zsh-syntax-highlighting # Syntax highlighting for commands
    colored-man-pages       # Colorful man pages
    extract                 # Universal archive extraction
)

# ----------------------------------------------------------
# SOURCE OH-MY-ZSH
# ----------------------------------------------------------
source "$ZSH/oh-my-zsh.sh"

# ----------------------------------------------------------
# HISTORY CONFIGURATION
# ----------------------------------------------------------
HISTFILE=~/.zsh_history
HISTSIZE=50000
SAVEHIST=50000

setopt HIST_IGNORE_ALL_DUPS   # Remove older duplicate entries from history
setopt HIST_IGNORE_SPACE      # Don't record commands starting with space
setopt HIST_REDUCE_BLANKS     # Remove superfluous blanks from history
setopt SHARE_HISTORY          # Share history between terminals
setopt EXTENDED_HISTORY       # Add timestamps to history
setopt INC_APPEND_HISTORY     # Add commands to history immediately

# ----------------------------------------------------------
# COLORED MAN PAGES
# ----------------------------------------------------------
export MANROFFOPT="-c"
export LESS="-R --use-color -Dd+r -Du+b"
export MANPAGER="less -R --use-color -Dd+r -Du+b"

# Fallback for older systems
export LESS_TERMCAP_mb=$'\e[1;31m'      # begin blink
export LESS_TERMCAP_md=$'\e[1;36m'      # begin bold
export LESS_TERMCAP_me=$'\e[0m'         # end mode
export LESS_TERMCAP_so=$'\e[01;44;33m'  # begin standout
export LESS_TERMCAP_se=$'\e[0m'         # end standout
export LESS_TERMCAP_us=$'\e[1;32m'      # begin underline
export LESS_TERMCAP_ue=$'\e[0m'         # end underline

# ----------------------------------------------------------
# ENVIRONMENT VARIABLES
# ----------------------------------------------------------
export EDITOR='nvim'
export VISUAL='nvim'
export PAGER='less'

# Add local bin to PATH
export PATH="$HOME/.local/bin:$PATH"

# ----------------------------------------------------------
# LOAD EXTERNAL ALIASES
# ----------------------------------------------------------
if [[ -f ~/.zshrc_aliases ]]; then
    source ~/.zshrc_aliases
fi

# ----------------------------------------------------------
# POWERLEVEL10K CONFIGURATION
# ----------------------------------------------------------
# To customize prompt, run `p10k configure` or edit ~/.p10k.zsh
[[ -f ~/.p10k.zsh ]] && source ~/.p10k.zsh

# ----------------------------------------------------------
# STARTUP
# ----------------------------------------------------------
# Display system info with fastfetch on interactive shells
if [[ $- == *i* ]] && command -v fastfetch &> /dev/null; then
    fastfetch
fi
