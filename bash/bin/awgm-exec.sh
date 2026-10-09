#!/usr/bin/env bash

#set -Eeuo pipefail

#-> Альяс этого скрипта если уже установлен и сделан source ~/.bash_profile
#me_alias=$(alias | grep awgm-exec.sh | awk '{print $2}' | cut -d'=' -f1)
me_alias="awgm"

#SELF="$(readlink -f "${BASH_SOURCE[0]}")"
#-> Новый SELF без файла на конце
SELF="$(dirname "$(readlink -f ${BASH_SOURCE[0]}"))"
BIN_DIR="${SELF}"
PARENT_DIR="$(dirname "${SELF}")"
#-> название проекта (берём название корневой папки)
PROJ_NAME=${PARENT_DIR##*/}
INCLUDE_DIR="${PARENT_DIR}/include"
env_inc="${INCLUDE_DIR}/.${PROJ_NAME}-env"
#-> Имя этого скрипта с расширением:
me_ext=$(basename "$0")
#-> Имя этого скрипта без расширения:
me="${me_ext%.*}"

dbg=0

### Подключаем инклюды:
#######################
source $env_inc
source $colors_inc
source $output_inc
source $input_inc

EXEC_SCRIPT="${SELF}/${me_ext}"
SRC_ROOT="${PARENT_DIR}"

#--- > Флаг дефолтного запуска сразу после билда.
#FlagRUN=true
cursor_blink_on
_tty_reset
#exit 0

### Запускалки:
###############1
dbg_cmd() { printf '%s\n' "$(cecho Ws "[#] $*")" >&2; "$@"; }
#color_cmd() { local cmd="$*"; { out=$($cmd); exit_code=$?; } && printf "$( '%s')\n" "${out}" || { printf "$(err_color '%s')\n" "${out}"; exit "$exit_code"; }; }
cmd() { printf '%s\n' "$*"; "$@"; }
die() { printf '%s\n' "$(err_color "${me}: $*")" >&2; exit 1; }

exec_test() {
echo $OUT_FILE
echo $SRC_DIR
echo $BUILD_SCRIPT
exit 0
}

#parse_cmd(){
#    local _cmd="$1" run_cmd="$2" arg1="$3" arg2="$4"
#    if ! echo "$_cmd" | cut -d'-' -f1 > /dev/null 2>&1; then
#        run_cmd="$_cmd"
#    else
#        run_cmd=$(echo "$_cmd" | cut -d'-' -f1)
#        arg1=$(echo "$_cmd" | cut -d'-' -f2)
#        f3=$(echo "$_cmd" | cut -d'-' -f3)
#        [ -n "$f3" ] 2>/dev/null && arg2="$f3" || true
#    fi
#}

#parse_cmd "exec-build-main" run_cmd arg1 arg2
#echo "$run_cmd $arg1 $arg2"

#exit 0
exec_cmd() {
    if [[ "$dbg" = 0 ]] > /dev/null 2>&1; then
        cmd bash "$@"
    else
        dbg_cmd bash "$@"
    fi
}

run_build() { bash ${BUILD_SCRIPT}; }
run_exec() {
   local run_obj="$1"
   bash ${run_obj}
#exit 0
}

_check(){
    if ! flock -n 9; then
        printstr "Скрипт уже запущен (lock: %s)\n" "${PROJ_LOCK_FILE}"
        return 0
    else
        return 1
    fi
}


show_help() {
    printf "$(cecho Ws '  Управление запуском скрипта') $(cecho Ys '%s')$(cecho Ws ':')\n" "$me_alias"
    echo -e "┌─────────────────────────────────────────────────────────────────┐"
    echo -e "│         Использование: sudo bash ${bgrn}${me_alias}${bnc} [${byell}ОПЦИИ${bnc}]                   │"
    echo -e "├─────────────────────────────────────────────────────────────────┤"
    echo -e "│                                                                 │"
    echo -e "│ $(cecho uWs "Опции:")                                                          ${bnc}│"
    echo -e "│  $(cecho sY "build | -b")            $bnc - Собрать скрипт                        │"
    echo -e "│  $(cecho sY "run   | -r")            $bnc - Запустить скрипт                      │"
    echo -e "│  $(cecho sY "test$ | -t")            $bnc - Запустить тестовую функцию и выйти    │"
    echo -e "│  $(cecho sY "help  | -h")            $bnc - Показать эту справку и выйти          │"
    echo -e "│  $(cecho sR "Запуск без аргументов") $bnc - Запустить default_run                 │"
    echo -e "│                                                                 │"
    echo -e "└─────────────────────────────────────────────────────────────────┘${nc}\n"
    exit "${EXIT_RC:-0}"
}

### Основная логика:
####################
#-> запускалка по умолчанию:
default_run() { exec_cmd ${BUILD_SCRIPT}; press_continue; exec_cmd ${MAIN_SCRIPT}; }

echo -e ${nc}
if [ "$#" -lt 1 ]; then
    default_run
else
#        if [ "$2" = "-y" ] || [ "$2" = "-Y" ]; then
#                commandConfirmed="true"
#        fi
        if [ "$1" = "build" ]||[ "$1" = "-b" ]; then
            exec_cmd ${BUILD_SCRIPT}
        elif [ "$1" = "start" ]||[ "$1" = "run" ]||[ "$1" = "-r" ]; then
            exec_cmd ${MAIN_SCRIPT}
        elif [ "$1" = "brun" ]||[ "$1" = "-br" ]; then
            exec_cmd ${BUILD_SCRIPT}
            press_continue
            exec_cmd ${MAIN_SCRIPT}
        elif [ "$1" = "help" ]||[ "$1" = "-h" ]; then
            show_help
        elif [ "$1" = "test" ]||[ "$1" = "-t" ]; then
            exec_test
        else
            show_help
        fi
fi
printf "%s\n" "$dashes"

exit 0

#ALLOWED_ARGS="-b build -r run -br brun -h help -t test"
#ALLOWED_CMDS="run-build run-main run-build-main show_help"

#validate_command() {
#    local cmd_name="$1"
#    shift
#    case " $ALLOWED_CMDS " in
#        *" $cmd_name "*) ;;
#        *) echo "Команды не разрешена"; return 1 ;;
#    esac
#    case "$cmd_name" in
#        run)   validate_find   "$@" ;;
#        grep)   validate_grep   "$@" ;;
#        sed)    validate_sed    "$@" ;;
#        od)     validate_od     "$@" ;;
#        tr)     validate_tr     "$@" ;;
#        mkdir)  validate_mkdir  "$@" ;;
#        rm)     validate_rm     "$@" ;;
#        *)      validate_simple_text "$@" ;;
#    esac
#}

# ----- main -----
#if [ "$#" -eq 0 ]; then
