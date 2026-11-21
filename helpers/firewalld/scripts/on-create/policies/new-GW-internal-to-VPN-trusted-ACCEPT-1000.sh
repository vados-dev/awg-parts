#!/usr/bin/env bash

. /root/.firewalld/.fw_cmd-env



me_ext=$(basename "$0")
me="${me_ext%.*}"
action="$(echo "$me" | cut -d'-' -f1)"
name1="$(echo "$me" | cut -d'-' -f2)"
name2="$(echo "$me" | cut -d'-' -f3)"
_ingress="$(echo "$me" | cut -d'-' -f3)"
name3="$(echo "$me" | cut -d'-' -f4)"
name4="$(echo "$me" | cut -d'-' -f5)"
name5="$(echo "$me" | cut -d'-' -f6)"
egress1="$(echo "$me" | cut -d'-' -f5)"
egress2="$(echo "$me" | cut -d'-' -f6)"
_egress="${egress1}-${egress2}"
target="$(echo "$me" | cut -d'-' -f7)"
priority="$(echo "$me" | cut -d'-' -f8)"
name="${name1}-${name2}-${name3}-${name4}-${name5}"
policy="policy $name"

desc=$(echo "'All network connections are accepted.'")
short="${name}"

setaction="--$action-$policy"

${fwperm} "${setaction}"
! [ -z "$target" ] && ${fwperm} "--$policy --set-target=$target"
! [ -z "$priority" ] && ${fwperm} "--$policy --set-priority=$priority"

for ingr in $_ingress; do
    ${fwperm} "--$policy --add-ingress-zone $ingr"
done
for egr in $_egress; do
    ${fwperm} "--$policy --add-egress-zone $egr"
done
${fwperm} --$policy "--set-description=${short}"
${fwperm} --$policy "--set-short=${short}"

${fwreload}
