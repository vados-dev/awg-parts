#!/bin/bash

fwcmd="firewall-cmd"
fwreload="${fwcmd} --reload"
fwperm="${fwcmd} --permanent"

#if [[ "$1" == "client" ]];then
#   ${fwperm} --remove-rich-rule='rule family=ipv4 source address='${2}'/24 masquerade'; ${fwreload};
#   ${fwperm} --remove-rich-rule='rule family=ipv6 source address='${3}'/24 masquerade'; ${fwreload};
#   ip route del 0.0.0.0/0 dev awg2vdsina
#   ip route del 10.9.0.0/24 dev awg0 proto kernel scope link src 10.9.0.3
#   ip route del 10.9.0.0/24 via 10.9.0.3 dev client
#   ip route add 0.0.0.0/0 via 10.30.30.81 dev eth0 proto static metric 100
#else
#   firewall-cmd --permanent --remove-port ${1}/udp; firewall-cmd --permanent --remove-rich-rule='rule family=ipv4 source address='${2}'/24 masquerade'; firewall-cmd --reload;
#   firewall-cmd --permanent --remove-rich-rule='rule family=ipv6 source address='${3}'/24 masquerade'
#fi
