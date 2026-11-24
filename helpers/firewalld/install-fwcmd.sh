#!/usr/bin/env bash

#### fwcmd — помощник с командами firewalld
###########################################
#-> Пути по умолчанию:
#    ------------------
#    Сам скрипт..."/usr/local/bin/fwcmd"
#    Симлинки....."/usr/local/bin/fwreload"
#                 "/usr/local/bin/fwperm"
#                 "/usr/local/bin/fwctl"
#
#-> Установка:
#    ----------
# $(mktemp -d -t install-fwcmd-XXXXXX)
#    Сохранить/переименовать в "install-fwcmd.sh" и запустить.
#    (После подтверждения, будет установлен со всеми симлинками в /usr/local/bin, а сам установщик будет удалён.)
#-> или:
#    "install-fwcmd.sh 1, если в неинтерактивном режиме, с автоподтверждением (1 — да, 0 — нет).
#    "install-fwcmd.sh [0|1] ~/bin", если в PATH.
#
#-> Проверка:
#    ---------
#    "fwcmd --version"....Должен вернуть номер версии
#    "fwcmdreload"........Должен ответить "success"
#
#######################################################
#-> Использование:
#    --------------
#    Сам скрипт один, при установке создаёт симлинки на самого себя.
#    Имя файла (симлинка), является первым аргументом (командой/функцией) при запуске скрипта. 
#    Отсюда:
#    `fwcmd`.............................`firewall-cmd`  - Примет любое количество, любых аргументов.
#                                                          Ответ будет получен от самомго firewall-cmd.
#    `fwreload`.................`firewall-cmd --reload`  - Перечитает правила. Аргументы не требуются.
#    `fwperm`................`firewall-cmd --permanent`  - Добавит/удалит соответствующее правило постоянно.
#                                                          Примет любое количество, любых аргументов.
#                                                          Ответ будет получен от самомго firewall-cmd.
#    `fwchk`.......`firewall-offline-cmd --check-config` - Проверит конфигурацию без применения.
#                                                          Аргументы не требуются.
#    `fwctl`..............`systemctl [команды] [служба]` - Управление служюой firewalld.
#    `[команда] [-h|--help]`...............................Покажет справку по fwcmd.
#
#
#    Управление службой:
#     - `fwctl [аргумент]`
#    Аргументы:
#     ----------
#     -e |enable.........Включить службу.
#     -d |disable........Выключить службу.
#     -en|enable-now.....Включить службу немедленно.
#     -dn|disable-now....Выключить службу немедленно.
#     -s |start..........Запустить службу.
#     -k |stop...........Остановить службу.
#     -r |restart........Перезапустить службу.
#     -rl|reload.........Перечитать и применить конфиги.
#     -st|status.........Показать статус службы.
#     -cc|chk_conf.......Проверить конфиги без применения (оффлайн).
#     -j |journ..........Показать журнал службы.
#     -h |--help.........Эта справка.
#

set -o pipefail

#-> Dynamic vars:
SELF="$(readlink -f "${BASH_SOURCE[0]}")"
SELF_DIR="$(dirname "${SELF}")"
PARENT_DIR="$(dirname "${SELF_DIR}")"

ME_SELF="${SELF##*/}"
ME_CLEAN="${ME_SELF%.*}"

me_name="${0##*/}"
ARGS=( "$@" )

#-> Static vars:
PROGRAM="fwcmd"
BIN_DIR="/usr/local/bin"
SYMLINKS=( "fwreload" "fwperm" "fwchk" "fwctl" )
assume_yes=0 # Автоматически отвечать "да" на все вопросы (для скриптов/cron)

fw_exec="firewall-cmd"

chk_cmd=firewall-offline-cmd
chk_args="--check-config"

fw_service="firewalld.service"
fwctl_exec="systemctl"

dbg=1 # Выводить отладочные сообщения

# Underscore → hyphen в значениях, чтобы '-' работал только как разделитель токенов
me() { printf '%s' "${me_name//_/-}"; }
me_args() { printf '%s' "${me_args//_/-}"; }

#case "$me_name" in
#  install-fwcmd.sh|install-fwcmd)
#    case " ${me_args[*]-} " in
#      *" -i "*|*" --install "*) : ;;   # ключ уже задан — не дублируем
#      *) set -- -i "$@" ;;
#    esac
#    ;;
#esac

if [ -t 0 ]; then
    #dbg_cmd() { local cmd="$*"; { out="$($cmd)"; exit_code=$?; } && printf '[\033[1;33m✨\033[0m]\033[1m %b \033[0m\n\033[1m %s \033[0m\n' "$@" "$out" || { printf '\033[1;31m %b \033[0m\n' "$out"; exit "$exit_code"; }; }
    cmd()  { printf '[\033[1;33m✨\033[0m]#: %s' "$*"; }
    color_cmd() { local cmd="$*"; { out="$($cmd)"; exit_code=$?; } && printf '\033[1;32m%s\033[0m\n' "$out" || { printf '\033[1;31m%s\033[0m\n' "$out"; }; }
    answer_box() { local out="$($*)" exit_code=$?; [ $exit_code -eq 0 ] && printf '\033[1;32m √ \033[1m%s\033[0m\n' "$out" || { printf '\033[1;31m ✘ \033[1m%s\033[0m\n' "$out"; }; }
    log()  { printf '\033[1;34m 📋 INFO:\033[0;8m [%s] - %s.\033[0m\n' "$me_name" "$*"; }
    warn() { printf '\033[1;33m ⚡ WARN:\033[0;1m [%s] - %s.\033[0m\n' "$me_name" "$*" >&2; }
    err()  { printf '\033[0;31m ⚫ ERROR:\033[0;1m [%s] - %s!\033[0m\n' "$me_name" "$*" >&2; }
    die()  { printf '\033[1;31m ❌ CRITICAL:\033[0;1m [%s] - %s!\033[0m\n' "$me_name" "$*" >&2; exit 1; }
    prompt_yn() { local def="$1"; [ "$def" == "y" ] && printf '\033[1m%s [Y/n]:\033[0m ' "$def" || printf '\033[1m%s [y/N]:\033[0m ' "$def"; }
    ok() { [ "$1" != "1" ] && printf '\033[1;32m √ %s\033[0m\n' "$2" || { printf '\033[1;31m ✘ %s\033[0m\n' "$2"; }; }
else
    cmd()  { printf '[*]#: `%s`\n' "$*"; }
    color_cmd() { local cmd="$*"; { out="$($cmd)"; exit_code=$?; } && printf '%s\n' "$out" || { printf '%s\n' "$out"; }; }
    answer_box() { local out="$($*)" exit_code=$?; [ $exit_code -eq 0 ] && printf ' √ %s\n' "$out" || { printf ' ✘ %s\n' "$out"; }; }
    log()  { printf '[INFO] [%s] - %s.\n' "$me_name" "$*"; }
    warn() { printf '[WARN] [%s] - %s.\n' "$me_name" "$*" >&2; }
    err()  { printf '[ERROR] [%s] - %s!\n' "$me_name" "$*" >&2; }
    die()  { printf '[CRITICAL] [%s] - %s!\n' "$me_name" "$*" >&2; exit 1; }
    prompt_yn() { [ "$2" == "y" ] && printf '%s [Y/n]: ' "$1" || printf '%s [y/N]: ' "$1"; }
    ok() { [ "$1" = "0" ] && printf ' √ %s\n' "$2" || { printf ' ✘ %s\n' "$2"; }; }
fi

dbg_cmd() { cmd $(printf '`\033[1m%s\033[0m`\n' "$*") >&2; "$@"; }
run_cmd() { [[ "$dbg" = 0 ]] > /dev/null 2>&1 && color_cmd "$*" || dbg_cmd "$*"; }

confirm() {
    local assume_yes="${1:-1}" prompt="${2:-Уверены?}" default="${3:-Y}"
    [ "$assume_yes" = "1" ] 
    [ -t 0 ] || die "Нет интерактивного терминала — используйте -y"
    read -r -p "$(prompt_yn "$prompt" "${default,,}")" a; [ "$a" = "y" ] && ok 0 "Подтверждено пользователем" || { ok 1 "Отменено пользователем"; exit 0; }
}

fwcmd_install() {
    [ "$1" = "-h" ] || [ "$1" = "--help" ] && { install_usage; exit 0; }
    [[ -z "$1" ]] || assume_yes="$1"; [[ -z "$2" ]] || BIN_DIR="$2"
    confirm "$assume_yes" "Установить ${PROGRAM} в ${BIN_DIR}?" "y" || { log "Установка отменена"; exit 0; }
    [ -d "$BIN_DIR" ] || mkdir -p "$BIN_DIR"
    install -m 755 ${me_name} "${BIN_DIR}/${PROGRAM}" || die "Ошибка установки ${PROGRAM}"
    log "установлена в ${BIN_DIR}/${PROGRAM}"
    log "создаю симлинки..."
    cd "${BIN_DIR}" || die "Ошибка перехода в ${BIN_DIR}"
    for link in "${SYMLINKS[@]}"; do
        ln -sf "${PROGRAM}" "${link}" || die "Ошибка создания симлинка ${link}"
        log "- ${link} -> ${PROGRAM}"
    done
    ok 1 "Установка завершена."
}

usage() { sed -n '25,43p' "${SELF}" | sed 's/^# \{0,1\}//'; }
install_usage() { sed -n '2,25p' "${SELF}" | sed 's/^# \{0,1\}//'; }
ctl_usage() { sed -n '42,60p' "${SELF}" | sed 's/^# \{0,1\}//'; }

fwctl_cmd() {
    [ $# -gt 0 ] || { err "Пустые аргументы"; ctl_usage; exit 2; }
    case $1 in
        -e|enable)          run_cmd $fwctl_exec enable $fw_service ;;
        -d|disable)         run_cmd $fwctl_exec disable $fw_service ;;
        -en|enable-now)     run_cmd $fwctl_exec enable --now $fw_service ;;
        -dn|disable-now)    run_cmd $fwctl_exec disable --now $fw_service ;;
        -s|start)           run_cmd $fwctl_exec start $fw_service ;;
        -k|stop)            run_cmd $fwctl_exec stop $fw_service ;;
        -r|restart)         run_cmd $fwctl_exec restart $fw_service ;;
        -rl|reload)         run_cmd $fw_exec --reload ;;
        -st|status)         run_cmd $fwctl_exec status $fw_service ;;
        -cc|chk_conf)       run_cmd $chk_cmd $chk_args ;;
        -j|journ)           run_cmd journalctl -xeu $fw_service ;;
        -h|--help)          ctl_usage ;;
        *) { err "Неизвестный аргумент '$1'"; ctl_usage; exit 2; } ;;
    esac
}

fw_cmd() {
    [ "${me_name}" != "install-fwcmd.sh" ] && ([ "$1" = "-h" ] || [ "$1" = "--help" ]) && { usage; exit 0; }
    case "${me_name}" in
        fwreload)           run_cmd $fw_exec --reload ;;
        fwperm)             run_cmd $fw_exec --permanent "$@" ;;
        fwchk)              run_cmd $chk_cmd $chk_args ;;
        fwctl)              fwctl_cmd "$@" ;;
        install-fwcmd.sh)   fwcmd_install "$@" ;;
        *)                  run_cmd $fw_exec "$@" ;;
    esac
}

fw_cmd "$@"
