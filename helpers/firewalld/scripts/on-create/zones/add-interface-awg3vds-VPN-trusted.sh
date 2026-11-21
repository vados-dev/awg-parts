#!/usr/bin/env bash

source /root/.firewalld/.fw_cmd-env

me_ext=$(basename "$0")
me="${me_ext%.*}"
actpref="$(echo "$me" | cut -d'-' -f1)"
actsuff="$(echo "$me" | cut -d'-' -f2)"
iface="$(echo "$me" | cut -d'-' -f3)"
pref="$(echo "$me" | cut -d'-' -f4)"
suff="$(echo "$me" | cut -d'-' -f5)"
[ -z "$suff" ] && name="${pref}" || name="${pref}-${suff}"
action="--${actpref}-${actsuff} $iface"
zone="--zone=$name"

setaction="$zone $action"
${fwperm} $setaction $name

sudo nmcli con modify $iface connection.zone $name

${fwreload}

sudo systemctl restart NetworkManager.service
sudo systemctl restart firewalld.service

#targets="dns http https VPN-awg2all-ports VPN-awg2home-ports VPN-wg2all-ports"
#for name in $targets; do
#    ${fwperm} $setaction $name
#done
#${fwperm} $addport
#${fwperm} --new-zone=$name;
#${fwperm} --zone=name --set-target=DROP
#${fwperm} --service=VPN-awg2all-ports --add-port=55055/udp;
#echo -e ${NC}"Permanet add service amneziawg: "${YELLOW} && firewall-cmd --permanent --zone=public --add-service=amneziawg && echo -e ${NC}"Done" && echo
#echo -e ${NC}"Permanet add service wireguard: "${YELLOW} && firewall-cmd --permanent --zone=public --add-service=wireguard && echo -e ${NC}"Done" && echo
