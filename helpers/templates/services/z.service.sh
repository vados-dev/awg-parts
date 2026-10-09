#!/bin/bash

#source ./configs/.portal-env

###################
### Переменные: ###
###################
SERVICE=awg-quick@awg3vds.service
#RELOAD_CMD=firewall-cmd
RELOAD_ARGS="--reload"
CHK_CONF_CMD=firewall-offline-cmd
CHK_CONF_ARGS="--check-config"
STOP_START="N"

portal_dir="${AWG_PORTAL_MAIN_DIR:=/etc/awg-portal}"
portal_service="${AWG_PORTAL_SERVICE_DIR:=/etc/systemd/system}"
cur_dir=$(cd $(dirname "$0") 2>/dev/null && pwd) || SCRIPT_DIR=".";

##############
### Цвета: ###
##############
red='\033[0;31m'; green='\033[0;32m'; blue='\033[0;34m'; yellow='\033[0;33m'; nc='\033[0m'; bold='\033[1m';
bred=${red}${bold}; bgreen=${green}${bold}; bblue=${blue}${bold}; byellow=${yellow}${bold}; bnc=${nc}${bold};

set -o pipefail

##############
### Flags: ###
##############
ENABLE=""; DISABLE=""; ENABLE_NOW=""; DISABLE_NOW=""; START=""; STOP=""; RESTART=""; STATUS=""; HELP=0;

############################
### Обработка аргументов ###
############################
NO_ARGS=0
COMMAND=""
HELP_EXIT_RC=0 # C1: 0 = явный help (exit 0); ставится в 1 для ошибок использования
ARGS=""
let $# || { NO_ARGS=1; HELP=1; }
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|enable)          ENABLE=1 ;;
        -d|disable)         DISABLE=1 ;;
        -en|enable-now)     ENABLE_NOW=1 ;;
        -dn|disable-now)    DISABLE_NOW=1 ;;
        -s|start)           START=1 ;;
        -k|stop)            STOP=1 ;;
        -r|restart)         RESTART=1 ;;
        -rl|reload)         COMMAND=$RELOAD_CMD; ARGS=$RELOAD_ARGS; break ;;
        -st|status)         STATUS=1 ;;
        -cc|chk_conf)       COMMAND=$CHK_CONF_CMD; ARGS=$CHK_CONF_ARGS; break ;;
        -j|journ)           COMMAND="journalctl"; HELP_EXIT_RC=0; ARGS="-xeu ${SERVICE}.service"; break ;;
        -h|--help)          COMMAND="help"; HELP_EXIT_RC=0; break ;;
        *) echo -e "\n ${bred}Неизвестный аргумент: ${byellow}$1${bred}!${nc}" >&2; COMMAND="help"; HELP_EXIT_RC=1;;
    esac
    shift
done

############################
### Проверка переменных: ###
############################
#cur_dir=$(pwd)
#cur_dir=$(cd "$(dirname "$0")" || exit && pwd)
#echo $AWG_PORTAL_MAIN_DIR
#echo $1
#exit 0


run_cmd() {
    if [ "$ARGS" = "restart" ] && [ "$STOP_START" = "Y" ]; then
        echo -e "${bnc} systemctl${bgreen} stop ${bnc}${SERVICE}${nc}"
        systemctl stop ${SERVICE}
        echo -e "${bnc} systemctl${bgreen} start ${bnc}${SERVICE}${nc}"
        systemctl start ${SERVICE}
    else
        echo -e "${bnc} systemctl${bgreen} $ARGS ${bnc}${SERVICE}${nc}"
        systemctl ${ARGS} ${SERVICE}
    fi
echo
}

show_help() {
    echo -e "${bold} Управление службой${byellow} ${SERVICE}${bnc}."
    echo -e "┌──────────────────────────────────────────────────────────────────┐"
    echo -e "│          Использование: sudo bash x.service.sh [${byellow}ОПЦИИ${bnc}]           │"
    echo -e "├──────────────────────────────────────────────────────────────────┤"
    echo -e "│ ${byellow}Опции${bnc}:                                                           │"
    echo -e "│   ${byellow}-e${bnc}, ${byellow}enable${bnc}            Включить службу                          │"
    echo -e "│   ${byellow}-d${bnc}, ${byellow}disable${bnc}           Выключить службу                         │"
    echo -e "│   ${byellow}-en${bnc}, ${byellow}enable-now${bnc}       Включить службу немедленно с остановкой  │"
    echo -e "│   ${byellow}-dn${bnc}, ${byellow}disable-now${bnc}      Выключить службу немедленно с остановкой │"
    echo -e "│   ${byellow}-s${bnc}, ${byellow}start${bnc}             Запустить                                │"
    echo -e "│   ${byellow}-k${bnc}, ${byellow}stop${bnc}              Остановить                               │"
    echo -e "│   ${byellow}-r${bnc}, ${byellow}restart${bnc}           Перезапустить                            │"
    echo -e "│   ${byellow}-rl${bnc}, ${byellow}reload${bnc}           Перечитать конфиги                       │"
    echo -e "│   ${byellow}-st${bnc}, ${byellow}status${bnc}           Показать статус службы                   │"
    echo -e "│   ${byellow}-cc${bnc}, ${byellow}chk_conf${bnc}         Проверить конфиги офлайн                 │"
    echo -e "│   ${byellow}-j${bnc}, ${byellow}journ${bnc}             Показать journalctl службы               │"
    echo -e "│   ${byellow}-h${bnc}, ${byellow}--help${bnc}            Показать эту справку и выйти             │"
    echo -e "│                                                                  │"
    echo -e "└──────────────────────────────────────────────────────────────────┘${nc}"
    # Явный --help завершается с 0; неизвестный аргумент - с 1 (ложный успех в CI).
    exit "${EXIT_RC:-0}"
}
#######################
### Основная логика ###
#######################
echo -e ${nc}
if [[ "$ENABLE" -eq 1 ]]; then      COMMAND="run_cmd"; ARGS="enable"; fi
if [[ "$DISABLE" -eq 1 ]]; then     COMMAND="run_cmd"; ARGS="disable"; fi
if [[ "$ENABLE_NOW" -eq 1 ]]; then  COMMAND="run_cmd"; ARGS="enable --now"; fi
if [[ "$DISABLE_NOW" -eq 1 ]]; then COMMAND="run_cmd"; ARGS="disable --now"; fi
if [[ "$START" -eq 1 ]]; then       COMMAND="run_cmd"; ARGS="start"; fi
if [[ "$STOP" -eq 1 ]]; then        COMMAND="run_cmd"; ARGS="stop"; fi
if [[ "$RESTART" -eq 1 ]]; then     COMMAND="run_cmd"; ARGS="restart"; fi
if [[ "$STATUS" -eq 1 ]]; then      COMMAND="run_cmd"; ARGS="status"; fi
#if [[ "$HELP" -eq 1 ]]; then        COMMAND="help"; fi

if [[ "$NO_ARGS" -eq 1 ]]; then echo -e " ${bred}Пустые аргументы [${byellow}ОПЦИИ${bred}]! ${bnc}\n${nc}"; COMMAND="help"; fi
if [[ "$COMMAND" == "help" ]]; then show_help "$HELP_EXIT_RC"; exit $HELP_EXIT_RC; fi
if [[ -z "$COMMAND" ]]; then show_help; else $COMMAND $ARGS; fi

#    cat << 'EOF'
#┌──────────────────────────────────────────────────────────────────┐
#│          Использование: sudo bash control.sh [ОПЦИИ]             │
#├──────────────────────────────────────────────────────────────────┤
#│ Опции:                                                           │
#│   -e, enable            Включить службу                          │
#│   -d, disable           Выключить службу                         │
#│   -en, enable-now       Включить службу немедленно с остановкой  │
#│   -dn, disable-now      Выключить службу немедленно с остановкой │
#│   -s, start             Запустить                                │
#│   -k, stop              Остановить                               │
#│   -r, restart           Перезапустить                            │
#│   -st, status           Показать статус службы                   │
#│   -h, --help            Показать эту справку и выйти             │
#│                                                                  │
#└──────────────────────────────────────────────────────────────────┘
#EOF
