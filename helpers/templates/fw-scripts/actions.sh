#!/usr/bin/env bash

### Основные переменные:
########################
#-> Статические системные:
SYSCONF_DIR="/etc"
#-> Статические корневые:
VPN_DIR="${SYSCONF_DIR}/VPN"
VPN_CONFIGS="${VPN_DIR}/configs"
VPN_TOOLS="${VPN_DIR}/tools"
VPN_HELPERS="${VPN_DIR}/helpers"

PROJ_NAME="awg-multitools"
INCLUDE_DIR="${VPN_TOOLS}/${PROJ_NAME}/include"

#-> Вычисленные:
SELF="$(readlink -f "${BASH_SOURCE[0]}")"
PARENT_DIR="${SELF%/*}"
#SELF_DIR=${SELF%/*}
#me_ext=$(basename "$0")
#me="${me_ext%.*}"
#action="$(echo "$me" | cut -d'Post' -f1)"

#-> Инклюды:
env_inc="${INCLUDE_DIR}/.${PROJ_NAME}-env"
colors_inc="${INCLUDE_DIR}/.${PROJ_NAME}-colors"
output_inc="${INCLUDE_DIR}/.${PROJ_NAME}-output"
input_inc="${INCLUDE_DIR}/.${PROJ_NAME}-input"
functions_inc="${INCLUDE_DIR}/.${PROJ_NAME}-functions"
firewalld_inc="${INCLUDE_DIR}/.${firewalld-env}"

[[ "${dbg:-0}" == "1" ]] && set -x

#-> Подключаем инклюды:
#######################
source $env_inc
source $colors_inc
source $output_inc
source $input_inc
source $functions_inc
source $firewalld_inc

warpif="$1"       # %i
awg3if="$2"
table="$3"       # таблица маршрутизации (200)
action="$4"      # up|down
mtu="${5:-1280}"
zone="${6:-public}"
ipv6="${7:-off}"

mss4=$(( mtu - 40 ))
mss6=$(( mtu - 60 ))

do_up() {
  ip rule add iif "$awg3if" lookup "$table" 2>/dev/null || true
  # Форвардинг awg0 -> туннель
  FW_Direct --add ipv4 filter FORWARD 0 -i $warpif -o "$awg3if" -j ACCEPT
  # Ответный трафик
  FW_Direct --add ipv4 filter FORWARD 0 -i "$warpif" -o "$awg3if" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  # NAT
  FW_Direct --add ipv4 nat POSTROUTING 0 -o "$warpif" -j MASQUERADE
  # MSS
  FW_Rich --add "$zone" rule family="ipv4" tcp-mss-clamp value="$mss4"

  if [[ "$ipv6" == "on" ]]; then
    FW_Direct --add ipv6 filter FORWARD 0 -i "$awg3if" -o "$warpif" -j ACCEPT
    FW_Direct --add ipv6 filter FORWARD 0 -i "$warpif" -o "$awg3if" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    FW_Direct --add ipv6 nat POSTROUTING 0 -o "$warpif" -j MASQUERADE
    FW_Rich --add "$zone" rule family="ipv6" tcp-mss-clamp value="$mss6"
  fi
}

do_down() {
  if [[ "$ipv6" == "on" ]]; then
    FW_Rich --remove "$zone" rule family="ipv6" tcp-mss-clamp value="$mss6"
    FW_Direct --remove ipv6 nat POSTROUTING 0 -o "$warpif" -j MASQUERADE
    FW_Direct --remove ipv6 filter FORWARD 0 -i "$warpif" -o "$awg3if" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    FW_Direct --remove ipv6 filter FORWARD 0 -i "$awg3if" -o "$warpif" -j ACCEPT
  fi

  FW_Rich --remove "$zone" rule family="ipv4" tcp-mss-clamp value="$mss4"
  FW_Direct --remove ipv4 nat POSTROUTING 0 -o "$warpif" -j MASQUERADE
  FW_Direct --remove ipv4 filter FORWARD 0 -i "$warpif" -o "$awg3if" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  FW_Direct --remove ipv4 filter FORWARD 0 -i "$awg3if" -o "$warpif" -j ACCEPT

  ip rule del iif "$awg3if" lookup "$table" 2>/dev/null || true
}

case "$action" in
  up)   do_up ;;
  down) do_down ;;
  *) echo "Использование: tunnel.sh <iface> <table> <up|down> [mtu] [zone] [ipv6]" >&2; exit 1 ;;
esac
