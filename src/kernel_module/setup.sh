#!/usr/bin/env bash

set -o pipefail

# Flags
INST_DEPS=0; RM_DEPS=0; SETUP_MOD=0; ADD_MOD=0; REINSTALL=0; UNINSTALL=0; HELP=0; HELP_EXIT_RC=0
#####################################################################################
SELF="$(readlink -f "${BASH_SOURCE[0]}")"
cur_dir=${SELF%/*}

amf="/etc/modules-load.d/amneziawg.conf"
wmf="/etc/modules-load.d/wireguard.conf"
DTSTAMP="$(date +'%Y%m%d%H%M')"
mod_tmp_ver="3.1-${DTSTAMP}"
mod_repo_owner="vados-dev"
#mod_repo_owner="amnezia-vpn"
mod_repo="amneziawg-linux-kernel-module-vds"
#mod_repo="amneziawg-linux-kernel-module"
mod_branch="master"

setup_tmp="${cur_dir}/${mod_repo}-${mod_tmp_ver}"

if [ "$#" -lt 1 ]; then
    HELP=1
else
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|deps)          INST_DEPS=1 ;;
            -rd|rmdeps)       RM_DEPS=1 ;;
            -s|setup)         SETUP_MOD=1 ;;
            -aa|addawg)       ADD_AWG=1 ;;
            -aw|addwg)        ADD_WG=1 ;;
            -da|delawg)       DEL_AWG=1 ;;
            -dw|delwg)        DEL_WG=1 ;;
            -r|reinstall)     REINSTALL=1 ;;
            -u|uninstall)     UNINSTALL=1 ;;
            -h|--help)        HELP=1 ;;
            *) echo "Неизвестный аргумент: $1" >&2; HELP=1; HELP_EXIT_RC=1;;
        esac
        shift
    done
fi
####################################################################################

install_deps() {
    dnf update -y
    dnf install -y dkms
    exit 0
}

remove_deps() {
    echo "dkms"
    dnf remove -y dkms
    exit 0
}

add_awg_to_modules() {
    mkdir -p "$(dirname "$amf")"
    if ! grep -qxF 'amneziawg' "$amf" 2>/dev/null; then
        echo "amneziawg" > "$amf" || log_warn "Write error $amf"
        echo "Added to $amf."
    fi
}

del_awg_from_modules() {
    rm -f $amf 2>/dev/null | echo "Remove error $amf"
    echo "$amf removed."
}


add_wg_to_modules() {
    mkdir -p "$(dirname "$wmf")"
    if ! grep -qxF 'wireguard' "$wmf" 2>/dev/null; then
        echo "wireguard" > "$wmf" || log_warn "Write error $wmf"
        echo "Added to $wmf."
    fi
}

del_wg_from_modules() {
    rm -f $wmf 2>/dev/null | echo "Remove error $wmf"
    echo "$wmf removed."
}


start_setup() {
    if ! dnf list installed "dkms" 2>/dev/null | grep -q "Installed Packages"; then
        install_deps
    fi
#    rm -rf ./setup-3.1
    git clone https://github.com/${mod_repo_owner}/${mod_repo}.git -b ${mod_branch} ${setup_tmp} > /dev/null 2>&1 | true
#    git clone https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git ./setup-3.1
#exit 0
    local mod_ver
    cd ${setup_tmp}/src && \
    ! command -v make print-version > /dev/null 2>&1 && mod_ver="$(make print-version)" || mod_ver="$(cat version.h | grep "define WIREGUARD_VERSION" | awk -F'[/" ]+' '{print $3}')" && \
#echo $mod_ver
#exit 0
    sudo make dkms-install && \
    sudo dkms install -m amneziawg -v ${mod_ver}
    add_awg_to_modules
#    add_wg_to_modules
    exit 0
}

start_remove() {
    sudo dkms remove "amneziawg/$(dkms status | grep amneziawg | awk -F'[/, ]+' '{print $2}' | head -1)" --all
    del_awg_from_modules
    del_wg_from_modules
    exit 0
}

show_help() {
    cat << 'EOF'
Использование: sudo bash setup.sh [ОПЦИИ]
Скрипт для установки модуля ядра AmneziaWG 2.0 на Centos 10 Stream.

Опции:
  -d, deps              Установить необходимые зависимости
  -rd, rmdeps           Удалить зависимости
  -s, setup             Установить модуль
  -aa, addawg           Добавить amneziawg модуль в автозагрузку
  -aw, addwg            Добавить wireguard модуль в автозагрузку
  -da, delawg           Удалить amneziawg модуль из автозагрузки
  -dw, delwg            Удалить wireguard модуль из автозагрузки
  -r, reinstall         Переустановить модуль
  -u, uninstall         Удалить DKMS регистрацию
  -h, --help            Показать эту справку и выйти

Для подписи модуля и использовании в Secure Boot:
Проверка включён ли Secure Boot:
mokutil --sb-state
Импорт ключа:
mokutil --import /var/lib/dkms/mok.pub

EOF
    # Явный --help завершается с 0; неизвестный аргумент - с 1 (ложный успех в CI).
    exit "${HELP_EXIT_RC:-0}"
}

if [[ "$HELP" -eq 1 ]]; then show_help; fi
if [[ "$INST_DEPS" -eq 1 ]]; then install_deps; fi
if [[ "$RM_DEPS" -eq 1 ]]; then remove_deps; fi
if [[ "$SETUP_MOD" -eq 1 ]]; then start_setup; fi
if [[ "$ADD_AWG" -eq 1 ]]; then add_awg_to_modules && exit 0; fi
if [[ "$ADD_WG" -eq 1 ]]; then add_wg_to_modules && exit 0; fi
if [[ "$DEL_AWG" -eq 1 ]]; then del_awg_from_modules && exit 0; fi
if [[ "$DEL_WG" -eq 1 ]]; then del_wg_from_modules && exit 0; fi
if [[ "$REINSTALL" -eq 1 ]]; then start_remove && start_setup; fi
if [[ "$UNINSTALL" -eq 1 ]]; then start_remove; fi
