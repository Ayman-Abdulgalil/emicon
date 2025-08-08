#!/usr/bin/env bash


UNATTENDED=0

while getopts "y" opt; do
  case ${opt} in
    y) UNATTENDED=1 ;;
    *) ;;
  esac
done

shift $((OPTIND-1))



# On error, exit
set -e

INSTALL_BIN="$HOME/.local/bin"
MOSINT_BIN="$INSTALL_BIN/mosint"

# Check if mosint is installed in PATH
if command -v mosint &>/dev/null; then
    echo "Mosint is already installed."
    exit 0
fi

echo "Mosint not found. Installing Mosint..."


# Check network/internet connectivity (HTTP, then ICMP as fallback)
if command -v curl &>/dev/null; then
    if ! curl -sSfI https://www.google.com >/dev/null; then
        echo "Error: Unable to reach https://www.google.com (HTTP request failed)."
        echo "Please check your network connection or proxy settings, then run this script again."
        exit 1
    fi
else
    if ! ping -c 1 8.8.8.8 &>/dev/null; then
        echo "Error: Network test (ICMP ping) failed."
        echo "Please check your internet/network connection, then run this script again."
        exit 1
    fi
fi


# Check if Go is installed
if command -v go &>/dev/null; then
    echo "Go is already installed."

else
    echo "Go is not installed."
    if [[ $UNATTENDED -eq 0 ]]; then
        read -p 'Do you want to install Go now? (y/n): ' answer
        if [[ $answer =~ ^[Nn]$ ]]; then
            echo "Go is required to install Mosint. Exiting."
            exit 1
        fi
    fi

    echo "Installing Go..."
    if [[ -f /etc/debian_version ]]; then
        sudo apt update && sudo apt install -y golang
    elif [[ -f /etc/redhat-release ]]; then
        sudo dnf install -y golang
    elif [[ -f /etc/arch-release ]]; then
        sudo pacman -Sy --noconfirm go
    elif [[ -f /etc/lsb-release ]] || grep -qi ubuntu /etc/os-release 2>/dev/null; then
        sudo apt update && sudo apt install -y golang
    else
        echo "Unsupported Linux distribution for automatic Go installation. Please install Go manually."
        exit 1
    fi

    if ! command -v go &>/dev/null; then
        echo "Go was not installed properly. Manual intervention needed."
        exit 1
    fi
fi

# Make sure destination bin dir exists and is in PATH
mkdir -p "$INSTALL_BIN"
if [[ ":$PATH:" != *":$INSTALL_BIN:"* ]]; then
    echo "Warning: $INSTALL_BIN is not in your PATH."
    echo "You should add it to your PATH, or change the '\$INSTALL_BIN' variable within this script."
    echo "e.g. add this line to your ~/.bashrc:"
    echo "export PATH=\"\$PATH:$INSTALL_BIN\""
fi

# Install Mosint
echo "Installing Mosint ..."
GOBIN="$INSTALL_BIN" go install -v github.com/alpkeskin/mosint/v3/cmd/mosint@latest

# Verification
if "$MOSINT_BIN" --version; then
    echo "Mosint was installed successfully at $MOSINT_BIN."
else
    echo "Error: Mosint was installed, but cannot be used. Manual intervention needed."
    exit 1
fi
