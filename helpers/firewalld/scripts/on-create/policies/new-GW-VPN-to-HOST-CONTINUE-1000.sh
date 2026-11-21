#!/usr/bin/env bash

. /root/.firewalld/.fw_cmd-env

me_ext=$(basename "$0")
me="${me_ext%.*}"
action="$(echo "$me" | cut -d'-' -f1)"
pref="$(echo "$me" | cut -d'-' -f2)"
suff="$(echo "$me" | cut -d'-' -f3)"
target="$(echo "$me" | cut -d'-' -f4)"
name="${pref}-${suff}"
zone="zone=$name"

desc=$(echo "'All network connections are accepted.'")
short="${name}"

setaction="--$action-$zone"

${fwperm} "${setaction}"
! [ -z "$target" ] && ${fwperm} "--$zone --set-target=$target"
${fwperm} --$zone "--set-description=${short}"
${fwperm} --$zone "--set-short=${short}"

${fwreload}
