#!/usr/bin/env bash

set -o pipefail
source /root/.bash_func

#########################
### Заготовки вывода: ###
#########################
COLS_NUM=79

_block() {
    local title="$1"
    local desc="$2"
printf "  ${bmag} ┌──────────────────────────────────────────────────────────────────────────────${nc}\n";
printf "  ${bmag} │   ${sym_star}${bnc}   $title   ${sym_star}                                   ${nc}\n";
printf "  ${bmag} └──────────────────────────────────────────────────────────────────────────────${nc}\n";
    if [[ -n "$desc" ]]; then
        printf "\n  ${bnc} %s${nc}\n" " ${desc//$'\n'/$'\n'  }"
    fi
    printf "${nc}${bmag}%s\n${bnc}" "    $dashes"
    printf "${nc}"
    printf -v MENUSTR "Меню раздела ${title}:"
}

_section() {
    local title="$1"
    local desc="$2"
printf "  ${bmag} ┌──────────────────────────────────────────────────────────────────────────────${nc}\n";
printf "  ${bmag} │   ${sym_star}${bnc}   $title   ${sym_star}                                   ${nc}\n";
printf "  ${bmag} └──────────────────────────────────────────────────────────────────────────────${nc}\n";
    if [[ -n "$desc" ]]; then
        printf "\n  ${bnc} %s${nc}\n" " ${desc//$'\n'/$'\n'  }"
    fi
    printf "${nc}${bmag}%s\n${bnc}" "    $dashes"
    printf "${nc}"
#    printf -v MENUSTR "Меню раздела ${title}:"
}
########################
### Обработка ошибок ###
########################
#tempfiles=( )
#cleanup() {
#  rm -f "${tempfiles[@]}"
#}
#trap cleanup 0
#error() {
#  local last_exit_status="$?"
##  local parent_lineno="$1"
##  local message="${2:-(no message ($last_exit_status))}"
##  local code="${3:-$last_exit_status}"
#  local parent_lineno="$1"
#  local message="$2"
#  local code="${3:-1}"
#  if [[ -n "$message" ]] ; then
#    echo "Error on or near line ${parent_lineno}: ${message}; exiting with status ${code}"
#  else
#    echo "Error on or near line ${parent_lineno}; exiting with status ${code}"
#  fi
#  exit "${code}"
#}
#trap 'error ${LINENO}' ERR
#shopt -s extdebug

##############
### Flags: ###
##############

###################
### Переменные: ###
###################
#cur_dir=$(pwd) #cur_dir=$(cd "$(dirname "$0")" || exit && pwd)
# Альяс команды firewall-cmd
#if [ "$fwcmd" = "" ] || [ ! "$fwcmd" ] || [ "$fwcmd" != $(which firewall-cmd) ]; then export fwcmd=$(which firewall-cmd); fi
fwcmd="/root/.firewalld/bin/fw-cmd"
# Ещё альясы
fwreload="${fwcmd} -rl"; fwperm="${fwcmd} -pmt";

#set +e
version="v0.0.1"
opt1=${1:-""}; opt2=${2:-""}; opt3=${3:-""}; opt4=${4:-""};

# setup for firewalld
# flags: noFW INPUTaccept LOaccept ssh authelia ZeroConfig web LogDrop UPnP hostapd icmpvisible

# defs
perm="--permanent"
permap="--permanent"
defzone="--zone=external"
zoneap="--zone=trusted"
ifap="ap0"
ap_iptsubn="10.3.141.0/24";
noif="lo $ifap";
# action
actn="add";
if [ "$opt2" == "delete" ] || [ "$opt2" == "remove" ]; then actn="remove"; fi

########################
### функции проверок ###
########################
function fw_check_xml { ! command -v grep "error" | /etc/firewalld/tools/check.sh >&2 || return 1; }

function check_ping {
local url="$1"; local hostname=$(echo "$url" | awk -F/ '{print $3}');
# Ping the hostname once and extract the RTT
rtt=$(ping -c 1 -W 1 "$hostname" 2>/dev/null | grep 'time=' | awk -F'time=' '{print $2}' | awk '{print $1}');
rtt=${rtt//.*/}; printstr "                   [%i] %sms %s\n" "$index" "$rtt" "$url";
}
function ip_check_v4 { curl --connect-timeout 1 ipinfo.io; }
function ip_check_v6 { curl --connect-timeout 1 v6.ipinfo.io; }

###############
### функции ###
###############
function mark { export $1=`pwd`; }
function _msg { echo -e `date +"%Y-%m-%d %T"` "$1"; }
function _stamp { _msg "$1$2 ##########################################################################"; }

function list-all {
  firewall-cmd --list-rich-rules
  firewall-cmd --get-active-zones
  firewall-cmd --get-default-zone
  firewall-cmd --get-zones
  return=$?
}


function IPT_DNS {
  _msg "FWD $1 filter: DNS $2 $3"
  firewall-cmd $3 $2 --$1-service=dns
  return $?
}

function IPT_DHCPserver {
  _msg "FWD $1 filter: DHCPserver $2 $3"
  firewall-cmd $3 $2 --$1-service=dhcp
  return $?
}

function IPT_DHCPclient {
  _msg "FWD $1 filter: DHCPclient $2 $3"
  firewall-cmd $3 $2 --$1-service=dhcpv6-client
  return $?
}

function IPT_ZeroConfig {
  _msg "FWD $1 filter: ZeroConfig $2 $3"
  firewall-cmd $3 $2 --$1-service=mdns
  return $?
}

function IPT_UPnP {
  _msg "FWD $1 filter: UPnP $2 $3"
  firewall-cmd $3 $2 --$1-service=upnp-client
  return $?
}

function IPT_nfs {
  _msg "FWD $1 filter: nfs $2 $3"
  firewall-cmd $3 $2 --$1-service=nfs --$1-service=nfs3 --$1-service=mountd --$1-service=rpc-bind
  return $?
}

function FWD_reload {
  _msg "FWD $1 filter: reload $2 $3"
  firewall-cmd --reload
  return $?
}

ret=0
case "$opt1" in
#  noFW)
#    IPT_noFW "$actn" "$zone" "$perm"
#    ret=$?
#    ;;
  IFadd)
    FWD_IFadd "$actn" "$zone" "$perm"
    ret=$?
    ;;
  DNS)
    IPT_DNS "$actn" "$zone" "$perm"
    ret=$?
    ;;
  DHCPserver)
    IPT_DHCPserver "$actn" "$zone" "$perm"
    ret=$?
    ;;
  DHCPclient)
    IPT_DHCPclient "$actn" "$zone" "$perm"
    ret=$?
    ;;
  ZeroConfig)
    IPT_ZeroConfig "$actn" "$zone" "$perm"
    ret=$?
    ;;
  UPnP)
    IPT_UPnP "$actn" "$zone" "$perm"
    ret=$?
    ;;
  nfs)
    IPT_nfs "$actn" "$zone" "$perm"
    ret=$?
    ;;
  reload)
    FWD_reload "$actn" "$zone" "$perm"
    ret=$?
    ;;
#  list-all)
#    list-all
#    ret=$?
#    ;;
  version)
    ret="$version"
    ;;
  *) echo # fwcmd "$1 $2 $3 $4"
    ;;

#    echo "Usage: ${0##*/} 4pump | list | version | noFW | IFadd | notICMPvisible | web | sambaclient | samba | mqtt | mqttws | DNS | ssh | mosh | rdp | rsync | CUPS | openVPN | NTP | cntlm | Warpin | fcgi | nodered | DHCPserver | syncthing | shellinabox | DHCPclient | ZeroConfig | UPnP | nfs | FAUXMO | ftp | ftps | hostapd | redis | redisHA | authelia | reload"
#    ret=1
esac
