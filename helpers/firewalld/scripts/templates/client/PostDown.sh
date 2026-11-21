#!/bin/bash

fwcmd="firewall-cmd"
fwreload="${fwcmd} --reload"
fwperm="${fwcmd} --permanent"


#if [[ "$1" == "client" ]];then
#   ${fwperm} --remove-rich-rule='rule family=ipv4 source address='${2}'/24 masquerade'; ${fwreload}; ${fwcmd} --set-default-zone=public; ${fwreload}; ${fwperm} --remove-port ${1}/udp; ${fwreload};
#   ${fwperm} --remove-rich-rule='rule family=ipv6 source address='${3}'/24 masquerade'; ${fwreload};
#else
#   firewall-cmd --permanent --remove-port ${2}/udp; firewall-cmd --permanent --remove-rich-rule='rule family=ipv4 source address='${3}'/24 masquerade'; firewall-cmd --reload;
#   firewall-cmd --permanent --remove-rich-rule='rule family=ipv6 source address='${3}'/24 masquerade'
#fi