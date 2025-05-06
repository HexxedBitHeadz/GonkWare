#!/bin/bash

# ┌────────────────────────────────────────┐
# │    Hexxed BitHeadz - GonkWare Setup    │
# └────────────────────────────────────────┘

clear

echo -e "\033[1;91m"
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

echo -e "\033[1;95m"
cat << "EOF"                      
[0x00] INIT > GONKWARE
[0x01] LOADING MODULES
[0x02] LINKING SHELLCODE ENGINE
[0x03] AI CO-PILOT READY
[0x04] INTERFACE ONLINE... █                                                        
EOF

sleep 1
echo -e "\033[0m"
echo "[+] Checking prerequisites..."

# Initialize array for missing packages
MISSING_PACKAGES=()

# --- Check for msfvenom ---
if ! command -v msfvenom &> /dev/null; then
    echo -e "\033[1;31m[!] Metasploit (msfvenom) not found!\033[0m"
    if ! command -v curl &> /dev/null; then
        echo -e "\033[1;31m[!] curl not found — required to install Metasploit!\033[0m"
        echo "    sudo apt install curl"
        MISSING_PACKAGES+=("curl")
    else
        echo "    Will attempt to install Metasploit using msfinstall script..."
    fi
    MISSING_PACKAGES+=("metasploit")
else
    echo -e "\033[1;32m[✓] Metasploit (msfvenom) is installed.\033[0m"
fi

# --- Check for Mono compiler ---
if ! command -v mcs &> /dev/null; then
    echo -e "\033[1;31m[!] Mono C# compiler (mcs) not found!\033[0m"
    echo "    sudo apt install mono-complete"
    MISSING_PACKAGES+=("mono-complete")
else
    echo -e "\033[1;32m[✓] Mono (mcs) is installed.\033[0m"
fi

# --- Check if python3-venv and ensurepip are working ---
python3 -m venv .venv_test 2> /dev/null
if [ $? -ne 0 ]; then
    echo -e "\033[1;31m[!] Failed to create a test venv — python3.10-venv or ensurepip is missing!\033[0m"
    echo "    sudo apt install python3.10-venv"
    MISSING_PACKAGES+=("python3.10-venv")
else
    echo -e "\033[1;32m[✓] Python venv module is working.\033[0m"
    rm -rf .venv_test
fi

# --- Check for tkinter ---
python3 -c "import tkinter" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "\033[1;31m[!] tkinter is missing (needed by ttkbootstrap)!\033[0m"
    echo "    sudo apt install python3.10-tk"
    MISSING_PACKAGES+=("python3.10-tk")
else
    echo -e "\033[1;32m[✓] tkinter is installed.\033[0m"
fi

# --- Check for xclip ---
if ! command -v xclip &> /dev/null; then
    echo -e "\033[1;31m[!] xclip is not installed (clipboard support)!\033[0m"
    echo "    sudo apt install xclip"
    MISSING_PACKAGES+=("xclip")
else
    echo -e "\033[1;32m[✓] xclip is installed.\033[0m"
fi

# --- Prompt to install missing packages ---
if [ ${#MISSING_PACKAGES[@]} -ne 0 ]; then
    echo -e "\n\033[1;93m[!] Missing packages detected:\033[0m ${MISSING_PACKAGES[*]}"
    read -p "Do you want to install them automatically? (Y/n): " choice
    case "$choice" in
        n|N )
            echo -e "\033[1;91m[✘] Exiting setup. Please install the missing packages manually.\033[0m"
            exit 1
            ;;
        * )
            echo -e "\033[1;92m[+] Installing missing packages: ${MISSING_PACKAGES[*]}...\033[0m"
            sudo apt update

            # Filter out "metasploit"
            PACKAGES_TO_INSTALL=()
            for pkg in "${MISSING_PACKAGES[@]}"; do
                if [ "$pkg" != "metasploit" ]; then
                    PACKAGES_TO_INSTALL+=("$pkg")
                fi
            done

            if [ ${#PACKAGES_TO_INSTALL[@]} -gt 0 ]; then
                sudo apt install -y "${PACKAGES_TO_INSTALL[@]}"
            fi

            if [[ " ${MISSING_PACKAGES[*]} " =~ " metasploit " ]]; then
                curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
                chmod 755 msfinstall && ./msfinstall
                echo -e "\033[1;93m[!] Don't forget to run 'msfconsole' to initialize the Metasploit database for first time!.\033[0m"
            fi
            ;;
    esac
fi

# --- Set up virtual environment ---
echo -e "\n[+] Creating Python virtual environment..."
python3 -m venv .GonkWare
source .GonkWare/bin/activate

# --- Install Python dependencies ---
if [ -f "requirements.txt" ]; then
    echo "[+] Installing from requirements.txt..."
    pip install --upgrade pip
    pip install -r requirements.txt
else
    echo "[!] requirements.txt not found — installing manually..."
    pip install --upgrade pip
    pip install \
        ttkbootstrap \
        Pillow \
        pyperclip \
        psutil \
        pycryptodome
fi

echo -e "\n\033[1;92m[✓] GonkWare environment is ready!\033[0m"
echo "  To start GonkWare:"
echo "   source .GonkWare/bin/activate"
echo "   python3 GonkWare.py"
