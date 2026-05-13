#!/bin/bash

if [ "${EUID}" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ "$ID" == 'ubuntu' ]] || [[ "$ID" == 'debian' ]]; then
		apt-get update
	    apt-get install -y libelf-dev linux-headers-$(uname -r) build-essential pkg-config curl wget unzip git patch wireguard-tools resolvconf
    elif [[ "$ID" == 'fedora' ]] || [[ "$ID" == 'oracle' ]]; then
        dnf install -y elfutils-libelf-devel kernel-devel pkg-config @development-tools curl wget unzip git patch wireguard-tools openresolv
	elif [[ "$ID" == 'centos' ]] || [[ "$ID" == 'almalinux' ]] || [[ "$ID" == 'rocky' ]]; then
		yum install -y elfutils-libelf-devel kernel-devel pkgconfig "@Development Tools" curl wget unzip git patch
	elif [[ "$ID" == 'arch' ]]; then
        pacman -S --needed --noconfirm linux-headers base-devel pkg-config curl wget unzip git patch wireguard-tools openresolv
	elif [[ "$ID" == 'alpine' ]]; then
		apk update
        apk add build-base linux-hardened-dev curl wget unzip git patch wireguard-tools openresolv
	fi
fi

START_DIR=$(pwd)
trap "cd $START_DIR" EXIT SIGINT SIGTERM

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TMP_DIR="$SCRIPT_DIR/temp-wg"
BRANCH="test3"

if [ -d "$TMP_DIR" ]; then
    rm -r "$TMP_DIR"
fi

function compileCompat() {
    TMP_ZIP="$SCRIPT_DIR/temp-wg.zip"

    wget -O "$TMP_ZIP" "https://github.com/mustaddon/wireguard-linux-compat/archive/refs/heads/$BRANCH.zip?t=$(date +%s)"
    unzip "$TMP_ZIP" -d "$TMP_DIR"

    CODE_DIR=$(find "$TMP_DIR" -type d -name "src")

    if [ ! -d "$CODE_DIR" ]; then
        echo "Error: Directory '$CODE_DIR' does not exist."
        exit 1
    fi

    rm -f "$TMP_ZIP"

    make -C "$CODE_DIR" -j$(nproc)
}

function compile() {
    git clone --branch "v$(uname -r | cut -d'.' -f1,2)" --single-branch --depth 1 --no-checkout https://github.com/torvalds/linux "$TMP_DIR"
    cd "$TMP_DIR"
    git sparse-checkout set drivers/net/wireguard
    git checkout

    CODE_DIR="$TMP_DIR/drivers/net/wireguard"

    if [ ! -d "$CODE_DIR" ]; then
        echo "Error: Directory '$CODE_DIR' does not exist."
        exit 1
    fi

    cd "$CODE_DIR"

    PATCH_FILE="$TMP_DIR/hwg.patch"

    curl -o "$PATCH_FILE" "https://raw.githubusercontent.com/mustaddon/wireguard-linux-compat/refs/heads/$BRANCH/kernel-tree-scripts/wg.patch?t=$(date +%s)"

    if patch -Np1 -f --dry-run < "$PATCH_FILE" > /dev/null 2>&1; then
        echo "No conflicts detected. Applying patch..."
        patch -Np1 -f < "$PATCH_FILE"
        echo "Patch applied."
    else
        echo "Conflict detected! Patch not applied."
        patch -Np1 -f --dry-run < "$PATCH_FILE"
        exit 1
    fi

    curl -O "https://raw.githubusercontent.com/mustaddon/wireguard-linux-compat/refs/heads/$BRANCH/src/{hidden.h,hidden.c,version.h}"

    make
}

MAJOR=$(uname -r | cut -d. -f1)
MINOR=$(uname -r | cut -d. -f2)

if [ "$MAJOR" -gt 5 ] || ([ "$MAJOR" -eq 5 ] && [ "$MINOR" -gt 5 ]); then
    compile
else
    compileCompat
fi

if [ ! -f "$CODE_DIR/wireguard.ko" ]; then
    echo "Error: File 'wireguard.ko' was not compiled."
    exit 1
fi

MOD_DIR=$(find "/lib/modules/$(uname -r)" -type d -name "wireguard")

if [ ! -d "$MOD_DIR" ]; then
    echo "Error: Wireguard module directory not found."
    exit 1
fi

modprobe -r wireguard
rm -rf "$MOD_DIR"/wireguard.ko*
cp "$CODE_DIR/wireguard.ko" "$MOD_DIR"
modprobe wireguard
dmesg | grep -i wireguard
systemctl restart wg-quick@*
