#!/usr/bin/env bash

###########
### INSTALL
### Устанавливает систему в окружение
#####################################

#set -o pipefail

### Основные переменные:
########################
#-> Статические системные:
SYSCONF_DIR="/etc"
SYSLOGS_DIR="/var/log"
SYSRUN_DIR="/var/run"
SYSTEMD_UNIT_DIR="/usr/lib/systemd/system"
AWG_SYSCONF="/etc/amnezia/amneziawg"
#-> Статические корневые:
VPN_DIR="${SYSCONF_DIR}/VPN"
VPN_CONFIGS="${VPN_DIR}/configs"
VPN_TOOLS="${VPN_DIR}/tools"
VPN_HELPERS="${VPN_DIR}/helpers"

#-> Вычисленные:
#SELF="$(readlink -f "${BASH_SOURCE[0]}")"
#-> Новый SELF без файла на конце
SELF="$(dirname $(readlink -f "${BASH_SOURCE[0]}"))"
BIN_DIR="${SELF}"
PARENT_DIR="$(dirname "${SELF}")"
#-> название проекта (берём название корневой папки)
PROJ_NAME=${PARENT_DIR##*/}
INCLUDE_DIR="${PARENT_DIR}/include"
SRC_DIR="${PARENT_DIR}/src"
SRC_SECURE_DIR="${PARENT_DIR:-.}/secure"
BUILD_SCRIPT="${PARENT_DIR}/build.sh"
PROJ_WORK_DIR="${VPN_TOOLS}/${PROJ_NAME}"
PROJ_LOCK_FILE="${SYSRUN_DIR}/${PROJ_NAME}.lock"

#-> Домашние:
HOME_DIR="${HOME:-/root}"
PROJ_ROOT_DIR="${HOME_DIR}/.${PROJ_NAME}"
PROJ_SECURE_DIR="${PROJ_ROOT_DIR}/.secure"
PROJ_BACKUPS_ROOT="${PROJ_ROOT_DIR}/.bak"
MAIN_SCRIPT="${PROJ_ROOT_DIR}/${PROJ_NAME}.sh"

#-> Инклюды:
env_inc="${INCLUDE_DIR}/.${PROJ_NAME}-env"
colors_inc="${INCLUDE_DIR}/.${PROJ_NAME}-colors"
output_inc="${INCLUDE_DIR}/.${PROJ_NAME}-output"
input_inc="${INCLUDE_DIR}/.${PROJ_NAME}-input"

source "${env_inc}"
source "${colors_inc}"
source "${output_inc}"
source "${input_inc}"

### Куда копируем:
##################
HOME_DIR="${HOME:-/root}"
PROFILE_FILE="${HOME_DIR}/.bashrc"
DST_ROOT="${HOME_DIR:-/root}/.${PROJ_NAME}"
DST_SECURE_DIR="${DST_ROOT}/.secure"

### Если папки нет, создаём:
############################
[ -d "$DST_ROOT" ] || [ -L "$DST_ROOT" ] && log_warn "Папка или симлинк $DST_ROOT уже существует." || { log "Папка $DST_ROOT не существует, создаю..."; mkdir -p $DST_ROOT; }
[ -d "$DST_SECURE_DIR" ] || [ -L "$DST_SECURE_DIR" ] && log_warn "Папка или симлинк $DST_SECURE_DIR уже существует." || { log "Папка $DST_SECURE_DIR не существует, создаю..."; mkdir -p $DST_SECURE_DIR; }
    log "Копирую ${SRC_SECURE_DIR} в $DST_SECURE_DIR..."
    cp -r ${SRC_SECURE_DIR}/* ${DST_SECURE_DIR}/ 2>/dev/null || true
    #find ${SRC_SECURE_DIR} -depth -name '.*' -exec cp -r {} ${DST_SECURE_DIR} \;

if [ -f ~/.bashrc ] && ! cat ~/.bashrc | grep "# start awg-multitools" > /dev/null 2>&1; then
    echo '' >> $PROFILE_FILE
    echo "# start ${PROJ_NAME}" >> $PROFILE_FILE
    echo "export AWGM_HOME=\"$PARENT_DIR\"" >> $PROFILE_FILE
    echo 'case ":$PATH:" in' >> $PROFILE_FILE
    echo '  *":$AWGM_HOME/bin:"*) ;;' >> $PROFILE_FILE
    echo '  *) export PATH="$AWGM_HOME:$AWGM_HOME/bin:$PATH" ;;' >> $PROFILE_FILE
    echo 'esac' >> $PROFILE_FILE
    echo '' >> $PROFILE_FILE
    echo "export AWGM_ROOT=\"$DST_ROOT\"" >> $PROFILE_FILE
    echo 'case ":$PATH:" in' >> $PROFILE_FILE
    echo '  *":$AWGM_ROOT/bin:"*) ;;' >> $PROFILE_FILE
    echo '  *) export PATH="$AWGM_ROOT:$PATH" ;;' >> $PROFILE_FILE
    echo 'esac' >> $PROFILE_FILE
    echo 'alias awgm=$(awgm-exec.sh "$@")' >> $PROFILE_FILE
    echo "# end ${PROJ_NAME}" >> $PROFILE_FILE
    source "${PROFILE_FILE}"
    ok_box "${PROFILE_FILE} записан."
else
    warning_box "В \"${PROFILE_FILE}\" уже есть нужные строки."
fi

printstr "$dashes"
