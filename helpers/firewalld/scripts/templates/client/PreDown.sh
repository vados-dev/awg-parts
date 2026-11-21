#!/usr/bin/env bash

cur_dir=$(cd $(dirname "$0") 2>/dev/null && pwd) || cur_dir=".";
dir_name="${PWD##*/}"; me_ext=$(basename "$0"); me="${me_ext%.*}";
[ -z "${1}" ]||[ -z "${2}" ] && exit 1
echo "ip route del ${1} via ${2} dev ${dir_name}"

#ip route del 109.107.177.79/32 via 10.10.10.1 dev awg2vds