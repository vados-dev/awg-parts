#!/bin/bash

fwcmd="firewall-cmd"
fwreload="${fwcmd} --reload"
fwperm="${fwcmd} --permanent"


if [[ "$1" == "client" ]];then
   ${fwperm} --add-port ${2}/udp; ${fwreload}; ${fwcmd} --set-default-zone=amneziawg; ${fwreload}; ${fwperm} --add-rich-rule='rule family=ipv4 source address='${3}'/24 masquerade'; ${fwreload};
#   ${fwperm} --add-rich-rule='rule family=ipv6 source address='${4}'/24 masquerade' ${fwreload};
#   ${fwperm} --set-default-zone=public;
#   ip route del 0.0.0.0/0 via 10.30.30.81 dev eth0
#   ip route add 0.0.0.0/0 dev awg2vdsina proto static metric 1
#   ip route add 10.9.0.0/24 dev awg0 proto kernel scope link src 10.9.0.3 metric 100
#   ip route add 0.0.0.0/0 via 10.30.30.81 dev eth0 proto static metric 100
else
   firewall-cmd --permanent --add-port ${1}/udp; firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address='${2}'/24 masquerade'; firewall-cmd --reload;
#   firewall-cmd --permanent --add-rich-rule='rule family=ipv6 source address='${3}'/24 masquerade'
fi
