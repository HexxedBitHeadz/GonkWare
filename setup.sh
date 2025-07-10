#!/usr/bin/env bash

# ┌────────────────────────────────────────┐
# │    Hexxed BitHeadz - GonkWare Setup    │
# └────────────────────────────────────────┘

# ── Color Codes ───────────────────────────
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;93m"
PINK="\033[1;95m"
RESET="\033[0m"
BOLDRED="\033[1;91m"

# ── Spinner Function ──────────────────────
show_progress_bar() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    echo -n "   "
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    echo " [✓]"
}

# ── Visual ────────────────────────────────
clear
echo -e "${BOLDRED}"
cat << "EOF"
  ▄████  ▒█████   ███▄    █  ██ ▄█▀ █     █░ ▄▄▄       ██▀███  ▓█████ 
 ██▒ ▀█▒▒██▒  ██▒ ██ ▀█   █  ██▄█▒ ▓█░ █ ░█░▒████▄    ▓██ ▒ ██▒▓█   ▀ 
▒██░▄▄▄░▒██░  ██▒▓██  ▀█ ██▒▓███▄░ ▒█░ █ ░█ ▒██  ▀█▄  ▓██ ░▄█ ▒▒███   
░▓█  ██▓▒██   ██░▓██▒  ▐▌██▒▓██ █▄ ░█░ █ ░█ ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓█  ▄ 
░▒▓███▀▒░ ████▓▒░▒██░   ▓██░▒██▒ █▄░░██▒██▓  ▓█   ▓██▒░██▓ ▒██▒░▒████▒
 ░▒   ▒ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ▒ ▒▒ ▓▒░ ▓░▒ ▒   ▒▒   ▓▒█░░ ▒▓ ░▒▓░░░ ▒░ ░
  ░   ░   ░ ▒ ▒░ ░ ░░   ░ ▒░░ ░▒ ▒░  ▒ ░ ░    ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ░  ░
░ ░   ░ ░ ░ ░ ▒     ░   ░ ░ ░ ░░ ░   ░   ░    ░   ▒     ░░   ░    ░   
      ░     ░ ░           ░ ░  ░       ░          ░  ░   ░        ░  ░
      
                             By Hexxed BitHeadz
EOF

echo -e "${PINK}"
cat << "EOF"                      
[0x00] INIT > GONKWARE
[0x01] LOADING MODULES
[0x02] LINKING SHELLCODE ENGINE
[0x03] HACKING THE PLANET
[0x04] INTERFACE ONLINE... █                                                        
EOF

sleep 1
echo -e "${RESET}"

# ── Prompt for sudo only if needed ────────
if [ ${#MISSING_PACKAGES[@]} -ne 0 ]; then
    if sudo -n true 2>/dev/null; then
        echo -e "${GREEN}[✓] Sudo is already authenticated.${RESET}"
    else
        echo -e "${YELLOW}[~] Sudo password required to install missing packages.${RESET}"
        sudo -v || { echo -e "${RED}[✘] Sudo authentication failed.${RESET}"; exit 1; }
    fi
fi

# ── Init ──────────────────────────────────
MISSING_PACKAGES=()
PYVER=$(python3 -c "import sys; print(f'python{sys.version_info.major}.{sys.version_info.minor}')")

# ── Check for binaries ────────────────────
if ! command -v msfvenom &> /dev/null; then
    echo -e "${RED}[!] Metasploit (msfvenom) not found!${RESET}"
	echo "    sudo snap install metasploit-framework"
    MISSING_PACKAGES+=("metasploit")
else
    echo -e "${GREEN}[✓] Metasploit (msfvenom) is installed.${RESET}"
fi

if ! command -v mcs &> /dev/null; then
    echo -e "${RED}[!] Mono C# compiler (mcs) not found!${RESET}"
    echo "    sudo apt install mono-complete"
    MISSING_PACKAGES+=("mono-complete")
else
    echo -e "${GREEN}[✓] Mono (mcs) is installed.${RESET}"
fi

python3 -m venv .venv_test &> /dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Failed to create venv — ${PYVER}-venv may be missing!${RESET}"
    echo "    sudo apt install ${PYVER}-venv"
    MISSING_PACKAGES+=("${PYVER}-venv")
else
    echo -e "${GREEN}[✓] Python venv module is working.${RESET}"
    rm -rf .venv_test
fi

python3 -c "import tkinter" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] tkinter missing (needed by ttkbootstrap)!${RESET}"
    echo "    sudo apt install ${PYVER}-tk"
    MISSING_PACKAGES+=("${PYVER}-tk")
else
    echo -e "${GREEN}[✓] tkinter is installed.${RESET}"
fi

if ! command -v xclip &> /dev/null; then
    echo -e "${RED}[!] xclip is not installed (clipboard support)!${RESET}"
    echo "    sudo apt install xclip"
    MISSING_PACKAGES+=("xclip")
else
    echo -e "${GREEN}[✓] xclip is installed.${RESET}"
fi

# ── Install Prompt ────────────────────────
if [ ${#MISSING_PACKAGES[@]} -ne 0 ]; then
    echo -e "\n${YELLOW}[!] Missing packages detected:${RESET} ${MISSING_PACKAGES[*]}"
    read -p "Do you want to install them automatically? (Y/n): " choice
    case "$choice" in
        n|N )
            echo -e "${RED}[✘] Exiting setup. Please install the missing packages manually.${RESET}"
            exit 1
            ;;
        * )
            echo -e "${GREEN}[+] Installing missing packages: ${MISSING_PACKAGES[*]}...${RESET}"

	    echo "[*] Running apt update..."
	    sudo -v || { echo -e "${RED}[✘] Sudo authentication failed.${RESET}"; exit 1; }
	    (sudo apt update &> /dev/null) & show_progress_bar $!

            PACKAGES_TO_INSTALL=()
            for pkg in "${MISSING_PACKAGES[@]}"; do
                if [ "$pkg" != "metasploit" ]; then
                    PACKAGES_TO_INSTALL+=("$pkg")
                fi
            done

            if [ ${#PACKAGES_TO_INSTALL[@]} -gt 0 ]; then
                echo -n "[*] Installing APT packages..."
                (sudo apt install -y "${PACKAGES_TO_INSTALL[@]}" &> /dev/null) & show_progress_bar $!
            fi

			if [[ " ${MISSING_PACKAGES[*]} " =~ " metasploit " ]]; then
				echo -n "[*] Installing Metasploit via Snap..."
				(sudo snap install metasploit-framework &> /dev/null) & show_progress_bar $!
				echo -n "[*] Initializing Metasploit database..."
				(echo yes | msfconsole --quiet --once > /dev/null 2>&1) & show_progress_bar $!
				echo -e "${YELLOW}[!] Metasploit is ready. You can run 'msfconsole' normally.${RESET}"
			fi
            ;;
    esac
fi

# ── Venv Setup ────────────────────────────
echo -e "\n[+] Creating Python virtual environment..."
python3 -m venv .GonkWare
if [ ! -f ".GonkWare/bin/activate" ]; then
    echo -e "${RED}[✘] Failed to create virtual environment!${RESET}"
    exit 1
fi
source .GonkWare/bin/activate

# ── Python Dependencies ───────────────────
if [ -f "requirements.txt" ]; then
    echo "[+] Installing from requirements.txt..."
    pip install --upgrade pip &> /dev/null
    pip install -r requirements.txt &> /dev/null
else
    echo "[!] requirements.txt not found — installing manually..."
    pip install --upgrade pip &> /dev/null
    pip install ttkbootstrap Pillow pyperclip psutil pycryptodome &> /dev/null
fi

# ── Done ──────────────────────────────────
echo -e "\n${GREEN}[✓] GonkWare environment is ready!${RESET}"
echo "  To start GonkWare:"
echo "   source .GonkWare/bin/activate"
echo "   python3 GonkWare.py"
