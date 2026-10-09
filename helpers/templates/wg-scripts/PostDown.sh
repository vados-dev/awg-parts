#!/bin/bash

firewall-cmd --permanent --remove-port ${1}/udp; firewall-cmd --permanent --remove-rich-rule='rule family=ipv4 source address='${2}'/24 masquerade'; firewall-cmd --reload; # firewall-cmd --permanent --remove-rich-rule='rule family=ipv6 source address='${3}'/24 masquerade'
