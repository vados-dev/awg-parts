#!/usr/bin/env bash

NO_COLORS=false

fetch_include() {
    local name=$1 url=$2 out
    out=$(mktemp)
    if ! curl -fsSL --max-time 10 "$url" > "$out"; then
        rm -f -- "$out"
        die "Failed to fetch $name"
    fi
    source "$out" || { rm -f -- "$out"; die "Invalid $name script"; }
    rm -f -- "$out"
}

INCLUDE_URL="https://raw.githubusercontent.com/vados-dev/awg-multitools/refs/heads/master/include"
colors_inc=".awg-multitools-colors"
output_inc=".awg-multitools-output"
input_inc=".awg-multitools-input"

fetch_include "colors" "${INCLUDE_URL}/${colors_inc}"
fetch_include "output"  "${INCLUDE_URL}/${output_inc}"
fetch_include "input"   "${INCLUDE_URL}/${input_inc}"


#slp() { sleep 7; }
#auto_log slp 15 "Cs" || echo -en "slp ERROR"
#cursor_blink_on

#Ee
set -uo pipefail
umask 077
export PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
SELF_DIR="$(dirname "${SELF}")"

ME_SELF="${SELF##*/}"
ME_CLEAN="${ME_SELF%.*}"

PROGRAM="${0##*/:-$ME_CLEAN}"
ARGS=( "$@" )

#-> Имя оригинального бинарника из amneziawg-tools
AWG_NAME="awg"
#-> Имя СКРИПТА для для которого создается симлинк
QUICK_NAME="${1:-awg-quick}"
AWG_INTERFACE="${ME_CLEAN}" #-> Запаска: #LNK_NAME="$(echo "$ME_CLEAN" | cut -d'-' -f1)"

cmd()  { printf '  [\033[1;33m✨\033[0m]\033[1m %s \033[0m\n' "$*" >&2; "$@"; }
log()  { printf ' \033[1;34m 📋 INFO:\033[0;8m [%s] - %s.\033[0m\n' "$PROGRAM" "$*"; }
warn() { printf ' \033[1;33m ⚡ WARN:\033[0;1m [%s] - %s.\033[0m\n' "$PROGRAM" "$*" >&2; }
err()  { printf ' \033[0;31m ⚫ ERROR:\033[0;1m [%s] - %s!\033[0m\n' "$PROGRAM" "$*" >&2; }
die()  { printf ' \033[1;31m ❌ CRITICAL:\033[0;1m [%s] - %s!\033[0m\n' "$PROGRAM" "$*" >&2; exit 1; }

AWG_BIN="$(which ${AWG_NAME})"
#[[ -f "${AWG_BIN}" ]] > /dev/null 2>&1 || { die "The oroginaly $AWG_NAME does not exist!"; exit 1; }
#[[ "${LNK_NAME}" = "${AWG_NAME}" || -r "${LNK_NAME}" ]] > /dev/null 2>&1 || { cd ${SELF_DIR} && ln -s "${AWG_NAME}" "${LNK_NAME}" 2>/dev/null || die "Symlink $LNK_NAME create failed!"; }

INTERFACE=${AWG_INTERFACE:-awg31adm}
KERNEL_REV=4569c4c67f3a57414969260cafbbd04694fbaae0
TOOLS_REV=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
SCRIPT_PATH=${SELF}
UI_BOLD= UI_DIM= UI_ACCENT= UI_RESET=
if [[ -t 2 && ${TERM:-dumb} != dumb && ! -v NO_COLOR ]]; then
    UI_BOLD=$'\e[1m' UI_DIM=$'\e[2m' UI_ACCENT=$'\e[36m' UI_RESET=$'\e[0m'
fi

ui_section() { printf '\n%s%s%s\n' "$UI_BOLD$UI_ACCENT" "$*" "$UI_RESET" >&2; }
ui_hint() { printf '  %s%s%s\n' "$UI_DIM" "$*" "$UI_RESET" >&2; }
ui_row() {
    local label=$1 value=$2 width=${COLUMNS:-80} available chunk rows columns
    if [[ -t 1 && ! -v COLUMNS ]]; then
        read -r rows columns < <(stty size 2>/dev/null) || true
        width=${columns:-80}
    fi
    [[ $width =~ ^[0-9]+$ ]] || width=80
    ((width >= 40)) || width=40
    ((width <= 100)) || width=100
    available=$((width - 22))
    printf '  %-17s : ' "$label"
    while ((${#value} > available)); do
        chunk=${value:0:available}
        printf '%s\n%22s' "$chunk" ''
        value=${value:available}
    done
    printf '%s\n' "$value"
}

firewall_label() {
    case $1 in 1) printf 'firewalld' ;;  2) printf 'UFW' ;; 3) printf 'nftables' ;; 4) printf 'Manual / unchanged' ;; esac
}

choose_firewall() {
    local key=$1
    ui_hint '1  firewalld      2  UFW     3  nftables     4  Manual (leave firewall unchanged)'
    plan_ask_validated "$key" 'Firewall' 1 valid_choice 1 2 3 4
}

fail() { die "$*" >&2; exit 1; }
usage() {
#    cat <<'EOF'
cecho Ws "Usage (run with sudo/root):\n"
  cecho Ys ${ME_SELF}; cecho Rs " controller1\n"
  cecho Ys ${ME_SELF}; cecho Rs " wizard\n"
  cecho Ys ${ME_SELF}; cecho Rs " install\n"
  cecho Ys ${ME_SELF}; cecho Rs " update\n"
  cecho Ys ${ME_SELF}; cecho Rs " kernel-check\n"
  cecho Ys ${ME_SELF}; cecho Rs " listener ENDPOINT [PORT [LOCAL_IP PEER_IP]]\n"
  cecho Ys ${ME_SELF}; cecho Rs " connector BUNDLE_FILE\n"
  cecho Ys ${ME_SELF}; cecho Rs " peer PUBLIC_KEY\n"
  cecho Ys ${ME_SELF}; cecho Rs " up\n"
  cecho Ys ${ME_SELF}; cecho Rs " migrate\n"
  cecho Ys ${ME_SELF}; cecho Rs " status\n"
  cecho Ys ${ME_SELF}; cecho Rs " verify\n"
  cecho Ys ${ME_SELF}; cecho Rs " firewall firewalld|ufw|nft\n\n"

cecho Ws "Defaults: interface $INTERFACE, UDP 51830, listener 10.203.77.1,
connector 10.203.77.2. Set AWG_INTERFACE to choose another interface.
listener saves a confidential AWG 3 bundle; connector prints its public key.
Run peer on the listener with that key, then up on both servers.
Table = off: only the peer tunnel /32 is added explicitly; LAN/default routes stay manual.
AWG_ALLOWED_IPS sets IPv4 peer networks; the peer tunnel address is always covered.
AWG_PLAN_FILE overrides the wizard/controller plan path (no passwords or keys).
Run without arguments to launch the step-by-step wizard.
Kernel-only AWG 3.1: install builds tools and a persistent DKMS module.
update preserves configuration and keys; loaded modules are never unloaded.
controller runs on either server or a separate Linux workstation (no local root
needed unless configuring this machine). SSH supports passwords, keys, agents,
custom ports, SSH config aliases and ProxyJump. Remote users need root or sudo.
\n"
#EOF
}

shell_quote() {
    local value=${1//\'/\'\\\'\'}
    printf "'%s'" "$value"
}

command_text() {
    local argument
    for argument in "$@"; do
        shell_quote "$argument"
        printf ' '
    done
}

declare -A NODE_MODE NODE_HOST NODE_USER NODE_PORT NODE_KEY NODE_JUMP NODE_ALLOWED NODE_FIREWALL NODE_UPLOAD PLAN

save_plan() {
    local target=$1 temporary key directory
    directory=$(dirname "$target")
    mkdir -p "$directory"
    temporary=$(mktemp "$directory/.awg-plan.XXXXXXXX")
    {
        printf '%s\n' AWG-PLAN-V1
        for key in "${!PLAN[@]}"; do
            printf '%s\t%s\n' "$key" "$(printf '%s' "${PLAN[$key]}" | base64 -w 0)"
        done
    } > "$temporary"
    chmod 600 "$temporary"
    mv -f -- "$temporary" "$target"
}

begin_plan() {
    local mode=$1 file marker key encoded value
    PLAN=()
    PLAN_REUSE=0
    PLAN_FILE=${AWG_PLAN_FILE:-${XDG_CONFIG_HOME:-$HOME/.config}/awg-s2s/$mode.plan}
    file=$PLAN_FILE
    [[ ! -f $PLAN_FILE.draft ]] || file=$PLAN_FILE.draft
    [[ -f $file ]] || return 0
    ui_section 'Saved setup found'
    ui_hint "$file"
    ui_hint '1  Review saved setup     2  Edit saved values     3  Start fresh'
    ask_validated 'How would you like to continue?' 1 valid_choice 1 2 3
    [[ $ANSWER != 3 ]] || return 0
    [[ $ANSWER != 1 ]] || PLAN_REUSE=1
    {
        read -r marker || fail "Empty plan file"
        [[ $marker == AWG-PLAN-V1 ]] || fail "Unsupported plan format"
        while IFS=$'\t' read -r key encoded; do
            [[ $key =~ ^(interface|endpoint|port|listener_ip|connector_ip|role|bundle_path|local_ip|peer_ip|local_allowed|local_firewall|listener_(mode|host|user|port|key|jump|allowed|firewall)|connector_(mode|host|user|port|key|jump|allowed|firewall))$ ]] || fail "Unknown saved plan field: $key"
            value=$(printf '%s' "$encoded" | base64 -d) || fail "Invalid saved plan encoding"
            [[ $value != *[[:cntrl:]]* ]] || fail "Invalid control characters in saved plan"
            PLAN[$key]=$value
        done
    } < "$file"
    ui_hint 'Saved values loaded. Nothing will run until you approve the review.'
}

ask_validated() {
    local prompt=$1 default=$2 validator=$3
    shift 3
    while true; do
        ask "$prompt" "$default"
        [[ $ANSWER != - ]] || ANSWER=
        if ( "$validator" "$ANSWER" "$@" ); then return; fi
        ui_hint 'Try again. Other values are unchanged.'
        default=
    done
}

plan_ask_validated() {
    local key=$1 prompt=$2 default=$3 validator=$4
    shift 4
    if [[ ${PLAN_REUSE:-0} == 1 && -v PLAN[$key] ]]; then
        if ( "$validator" "${PLAN[$key]}" "$@" ); then
            ANSWER=${PLAN[$key]}
            return
        fi
        ui_hint 'A saved value needs attention:'
    fi
    ask_validated "$prompt" "${PLAN[$key]:-$default}" "$validator" "$@"
    PLAN[$key]=$ANSWER
    save_plan "$PLAN_FILE.draft"
}

valid_choice() {
    local value=$1 option
    shift
    for option in "$@"; do [[ $value != "$option" ]] || return 0; done
    fail "Choose one of: $*"
}

valid_host() {
    [[ $1 =~ ^[a-zA-Z0-9][a-zA-Z0-9_.:-]*$ ]] || fail "Invalid SSH hostname/IP/alias"
}

valid_endpoint() {
    [[ $1 =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ ]] || fail "Endpoint must be a hostname or IPv4 address"
}

valid_username() {
    [[ -z $1 || $1 =~ ^[a-zA-Z_][a-zA-Z0-9_-]*$ ]] || fail "Invalid SSH username"
}

valid_port() {
    [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && (($1 <= 65535)) || fail "Port must be 1..65535"
}

valid_optional_port() {
    [[ -z $1 ]] || valid_port "$1"
}

valid_key_file() {
    [[ -z $1 || -f $1 ]] || fail "SSH key file does not exist"
}

valid_jump() {
    [[ -z $1 || $1 != -* && $1 != *[[:space:]]* ]] || fail "Invalid jump host"
}

valid_interface() {
    [[ $1 =~ ^[a-zA-Z][a-zA-Z0-9-]{0,14}$ ]] || fail "Interface must start with a letter and contain 1..15 letters, digits or hyphens"
}

valid_peer_ip() {
    valid_ip "$1"
    [[ $1 != "$2" ]] || fail "Tunnel addresses must differ"
}

valid_optional_key() {
    [[ -z $1 ]] || valid_key "$1"
}

valid_bundle_file() {
    local -a values
    [[ -f $1 ]] || fail "Bundle file does not exist"
    mapfile -t values < "$1"
    [[ ${#values[@]} -eq 8 && ${values[0]} == AWG-SITE-V3 ]] || fail "AWG-SITE-V3 bundle required"
    valid_endpoint "${values[1]}"; valid_port "${values[2]}"
    valid_ip "${values[3]}"; valid_peer_ip "${values[4]}" "${values[3]}"
    valid_key "${values[5]}"; valid_key "${values[6]}"; valid_key "${values[7]}"
}

approve_plan() {
    local resume_file=$PLAN_FILE
    [[ ! -f $PLAN_FILE.draft ]] || resume_file=$PLAN_FILE.draft
    ui_section 'Ready to apply?'
    ui_hint '1  Save and apply     2  Edit settings     3  Exit without changes'
    ask_validated 'Choose an action' 3 valid_choice 1 2 3
    case $ANSWER in
        2) return 2 ;;
        3) ui_hint "Nothing applied. Saved setup: $resume_file"; return 1 ;;
    esac
    save_plan "$PLAN_FILE" || fail "Cannot save the confirmed plan; no server changes applied"
    rm -f -- "$PLAN_FILE.draft"
    ui_hint "Plan saved: $PLAN_FILE"
}

node_label() {
    local node=$1
    if [[ ${NODE_MODE[$node]} == local ]]; then
        printf '%s: %s (this machine)' "$node" "$(hostname)"
    else
        printf '%s: %s%s [SSH, port %s]' "$node" "${NODE_USER[$node]:+${NODE_USER[$node]}@}" "${NODE_HOST[$node]}" "${NODE_PORT[$node]:-from config / default 22}"
    fi
}

node_notice() { printf '\n[%s] %s\n' "$(node_label "$1")" "$2" >&2; }

configuration_table() {
    local listener_ip=$1 connector_ip=$2 endpoint=$3 port=$4 node tunnel_ip
    ui_section '4 / 4  Review configuration'
    ui_row Interface "$INTERFACE"
    ui_row Protocol 'AmneziaWG 3.1 / kernel only'
    ui_row Routing 'Peer /32 automatic; other routes manual'
    for node in listener connector; do
        ui_section "$node"
        ui_row Server "$(node_label "$node")"
        if [[ $node == listener ]]; then tunnel_ip=$listener_ip; else tunnel_ip=$connector_ip; fi
        ui_row 'Tunnel address' "$tunnel_ip/32"
        ui_row AllowedIPs "${NODE_ALLOWED[$node]}"
        if [[ $node == listener ]]; then
            ui_row UDP "Listen on port $port"
        else
            ui_row UDP "$endpoint:$port"
        fi
        ui_row Firewall "$(firewall_label "${NODE_FIREWALL[$node]}")"
        if [[ ${NODE_MODE[$node]} == ssh ]]; then
            ui_row Authentication "${NODE_KEY[$node]:-SSH agent / default keys / password}"
            [[ -z ${NODE_JUMP[$node]} ]] || ui_row 'Jump host' "${NODE_JUMP[$node]}"
        fi
    done
    ui_section 'Before applying'
    ui_hint "Allow UDP $port on the listener and in the provider firewall."
    ui_hint 'Only the peer tunnel /32 route is added. LAN and default routes remain manual.'
    ui_hint 'Automatic firewall modes allow all local services from the peer tunnel IP.'
    ui_hint 'Existing profiles must match. Keys and configurations are not silently replaced.'
}

connection_details() {
    local node=$1
    ui_section "Connect to $node"
    ui_hint '1  Remote server (SSH)     2  This machine'
    local default_mode=1
    [[ ${PLAN[${node}_mode]:-} != local ]] || default_mode=2
    case ${PLAN[${node}_mode]:-} in ssh) PLAN[${node}_mode]=1 ;; local) PLAN[${node}_mode]=2 ;; esac
    plan_ask_validated "${node}_mode" "Connection type" "$default_mode" valid_choice 1 2 ssh local
    case $ANSWER in
        1|ssh) NODE_MODE[$node]=ssh ;;
        2|local) NODE_MODE[$node]=local
            NODE_HOST[$node]= NODE_USER[$node]= NODE_PORT[$node]= NODE_KEY[$node]= NODE_JUMP[$node]=
            PLAN[${node}_mode]=local; save_plan "$PLAN_FILE.draft"; return ;;
        *) fail "Choose SSH (1) or this machine (2)" ;;
    esac
    PLAN[${node}_mode]=ssh
    plan_ask_validated "${node}_host" "Host / SSH alias" "" valid_host
    NODE_HOST[$node]=$ANSWER
    plan_ask_validated "${node}_user" "SSH user (optional)" "" valid_username
    NODE_USER[$node]=$ANSWER
    plan_ask_validated "${node}_port" "SSH port (optional)" "" valid_optional_port
    NODE_PORT[$node]=$ANSWER
    local advanced=no
    [[ -z ${PLAN[${node}_key]:-}${PLAN[${node}_jump]:-} ]] || advanced=yes
    if [[ ${PLAN_REUSE:-0} != 1 ]]; then
        ui_hint 'SSH uses your normal keys, agent or password. Empty fields use SSH config.'
        ask_validated 'Custom key or jump host? (yes/no)' "$advanced" valid_choice yes y no n
        advanced=$ANSWER
    fi
    if [[ $advanced == no || $advanced == n ]]; then
        NODE_KEY[$node]= NODE_JUMP[$node]= PLAN[${node}_key]= PLAN[${node}_jump]=
        save_plan "$PLAN_FILE.draft"
        return
    fi
    plan_ask_validated "${node}_key" "SSH key path (optional)" "" valid_key_file
    NODE_KEY[$node]=$ANSWER
    plan_ask_validated "${node}_jump" "Jump host (optional)" "" valid_jump
    NODE_JUMP[$node]=$ANSWER
}

ssh_arguments() {
    local node=$1
    SSH_ARGS=(-o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=3
        -o ControlMaster=auto -o ControlPersist=600 -o "ControlPath=$CONTROL_DIR/$node-%C")
    [[ -z ${NODE_USER[$node]} ]] || SSH_ARGS+=(-l "${NODE_USER[$node]}")
    [[ -z ${NODE_PORT[$node]} ]] || SSH_ARGS+=(-p "${NODE_PORT[$node]}")
    [[ -z ${NODE_KEY[$node]} ]] || SSH_ARGS+=(-i "${NODE_KEY[$node]}" -o IdentitiesOnly=yes)
    [[ -z ${NODE_JUMP[$node]} ]] || SSH_ARGS+=(-J "${NODE_JUMP[$node]}")
}

on_node() {
    local node=$1 text=$2 wrapped
    [[ -n ${NODE_ACTION:-} ]] || node_notice "$node" 'Preparing configuration (privileged)'
    if [[ ${NODE_MODE[$node]} == local ]]; then
        if [[ $EUID == 0 ]]; then bash -c "$text"; else sudo -- bash -c "$text"; fi
    else
        ssh_arguments "$node"
        wrapped="if [ \"\$(id -u)\" = 0 ]; then bash -c $(shell_quote "$text"); else sudo -- bash -c $(shell_quote "$text"); fi"
        ssh -tt "${SSH_ARGS[@]}" "${NODE_HOST[$node]}" "$wrapped"
    fi
}

node_command() {
    local node=$1
    shift
    node_notice "$node" "$1"
    local NODE_ACTION=$1
    on_node "$node" "$(command_text env "AWG_INTERFACE=$INTERFACE" "AWG_ALLOWED_IPS=${NODE_ALLOWED[$node]}" "AWG_UI_ACTION=$1" bash "$REMOTE_SCRIPT" "$@")"
}

upload_script() {
    local node=$1 uploaded=$SCRIPT_PATH temporary= status text cleanup
    node_notice "$node" 'Installing setup script'
    if [[ ${NODE_MODE[$node]} == ssh ]]; then
        ssh_arguments "$node"
        temporary=$(ssh -T "${SSH_ARGS[@]}" "${NODE_HOST[$node]}" 'set -e; umask 077; path=$(mktemp /tmp/amnezia-upload.XXXXXXXX); trap '\''rm -f -- "$path"'\'' EXIT; cat > "$path"; printf "%s\n" "$path"; trap - EXIT' < "$SCRIPT_PATH")
        [[ $temporary =~ ^/tmp/amnezia-upload\.[a-zA-Z0-9]{8}$ ]] || fail "Unexpected upload path returned by $node"
        uploaded=$temporary
        NODE_UPLOAD[$node]=$temporary
    fi
    text="set -e; umask 077; mkdir -p /usr/local/lib; bash -n $(shell_quote "$uploaded"); install -m 700 $(shell_quote "$uploaded") $(shell_quote "$REMOTE_SCRIPT.new"); mv -f $(shell_quote "$REMOTE_SCRIPT.new") $(shell_quote "$REMOTE_SCRIPT")"
    if on_node "$node" "$text"; then status=0; else status=$?; fi
    if [[ -n $temporary ]]; then
        cleanup=$(command_text rm -f -- "$temporary")
        ssh -T "${SSH_ARGS[@]}" "${NODE_HOST[$node]}" "$cleanup" || fail "Could not remove uploaded temporary script on $node"
        unset 'NODE_UPLOAD[$node]'
    fi
    return "$status"
}

controller_cleanup() {
    local node
    for node in listener connector; do
        if [[ ${NODE_MODE[$node]:-} == ssh ]]; then
            ssh_arguments "$node"
            if [[ -n ${NODE_UPLOAD[$node]:-} ]]; then
                ssh -T "${SSH_ARGS[@]}" "${NODE_HOST[$node]}" "$(command_text rm -f -- "${NODE_UPLOAD[$node]}")" >/dev/null 2>&1 || true
            fi
            ssh "${SSH_ARGS[@]}" -O exit "${NODE_HOST[$node]}" >/dev/null 2>&1 || true
        fi
    done
    if [[ ${CONTROL_DIR:-} == /tmp/amnezia-controller.* ]]; then
        rm -rf -- "$CONTROL_DIR"
    fi
}

exchange_from_node() {
    local node=$1 file=$2 remote_uid text administrator_password
    node_notice "$node" "Reading $file (contents hidden)"
    if [[ ${NODE_MODE[$node]} == local ]]; then
        if [[ $EUID == 0 ]]; then EXCHANGE=$(cat "$file"); else EXCHANGE=$(sudo -- cat "$file"); fi
    else
        ssh_arguments "$node"
        remote_uid=$(ssh -T "${SSH_ARGS[@]}" "${NODE_HOST[$node]}" 'id -u')
        text=$(command_text cat "$file")
        if [[ $remote_uid == 0 ]]; then
            EXCHANGE=$(ssh -T "${SSH_ARGS[@]}" "${NODE_HOST[$node]}" "$text")
        elif ssh -T "${SSH_ARGS[@]}" "${NODE_HOST[$node]}" "sudo -n -- bash -c ':'" >/dev/null 2>&1; then
            EXCHANGE=$(ssh -T "${SSH_ARGS[@]}" "${NODE_HOST[$node]}" "sudo -n -- bash -c $(shell_quote "$text")")
        else
            read -r -s -p "Sudo password for $node (for confidential transfer): " administrator_password </dev/tty || fail "Input closed"
            printf '\n' >/dev/tty
            EXCHANGE=$(printf '%s\n' "$administrator_password" | ssh -T "${SSH_ARGS[@]}" "${NODE_HOST[$node]}" "sudo -S -p '' -- bash -c $(shell_quote "$text")")
            unset administrator_password
        fi
    fi
    [[ -n $EXCHANGE ]] || fail "Could not retrieve exchange information from $node"
}

collect_controller_plan() {
    connection_details listener
    connection_details connector
    while [[ ${NODE_MODE[listener]} == local && ${NODE_MODE[connector]} == local ]]; do
        echo "Both ends cannot be this machine; choose another connector connection." >&2
        PLAN_REUSE=0
        connection_details connector
    done
    ui_section '1 / 4  Tunnel settings'
    plan_ask_validated interface "Tunnel interface name" "$INTERFACE" valid_interface; INTERFACE=$ANSWER; set_paths
    plan_ask_validated endpoint "Listener public UDP host" "${NODE_HOST[listener]:-}" valid_endpoint
    endpoint=$ANSWER
    plan_ask_validated port "Tunnel UDP port" 1443 valid_port; port=$ANSWER
    plan_ask_validated listener_ip "Listener tunnel IPv4 address" 10.78.78.1 valid_ip; listener_ip=$ANSWER
    plan_ask_validated connector_ip "Connector tunnel IPv4 address" 10.78.78.2 valid_peer_ip "$listener_ip"; connector_ip=$ANSWER
    ui_section '2 / 4  Peer addresses'
    ui_hint 'Enter CIDRs separated by commas or spaces. /0 is allowed; only the peer /32 gets a route.'
    ui_hint 'Each field describes addresses reachable THROUGH THE OTHER SERVER.'
    for node in listener connector; do
        if [[ $node == listener ]]; then
            plan_ask_validated "${node}_allowed" "Via connector (on listener)" "$connector_ip/32" normalize_allowed_ips "$connector_ip" "$listener_ip"
            normalize_allowed_ips "$ANSWER" "$connector_ip" "$listener_ip"
        else
            plan_ask_validated "${node}_allowed" "Via listener (on connector)" "$listener_ip/32" normalize_allowed_ips "$listener_ip" "$connector_ip"
            normalize_allowed_ips "$ANSWER" "$listener_ip" "$connector_ip"
        fi
        NODE_ALLOWED[$node]=$ALLOWED_IPS
        PLAN[${node}_allowed]=$ALLOWED_IPS
    done
    ui_section '3 / 4  Firewall'
    ui_hint 'Manual is recommended if you already manage the firewall.'
    for node in listener connector; do
        ui_hint "$(node_label "$node")"
        choose_firewall "${node}_firewall"
        NODE_FIREWALL[$node]=$ANSWER
    done
    echo
    configuration_table "$listener_ip" "$connector_ip" "$endpoint" "$port"
}

restore_controller_plan() {
    local required node peer_ip local_ip
    for required in interface endpoint port listener_ip connector_ip listener_allowed connector_allowed listener_firewall connector_firewall listener_mode connector_mode; do
        [[ -v PLAN[$required] ]] || return 1
    done
    INTERFACE=${PLAN[interface]}; valid_interface "$INTERFACE"; set_paths
    endpoint=${PLAN[endpoint]}; valid_endpoint "$endpoint"
    port=${PLAN[port]}; valid_port "$port"
    listener_ip=${PLAN[listener_ip]}; valid_ip "$listener_ip"
    connector_ip=${PLAN[connector_ip]}; valid_peer_ip "$connector_ip" "$listener_ip"
    for node in listener connector; do
        NODE_MODE[$node]=${PLAN[${node}_mode]}
        valid_choice "${NODE_MODE[$node]}" ssh local
        NODE_HOST[$node]=${PLAN[${node}_host]:-} NODE_USER[$node]=${PLAN[${node}_user]:-}
        NODE_PORT[$node]=${PLAN[${node}_port]:-} NODE_KEY[$node]=${PLAN[${node}_key]:-} NODE_JUMP[$node]=${PLAN[${node}_jump]:-}
        if [[ ${NODE_MODE[$node]} == ssh ]]; then
            valid_host "${NODE_HOST[$node]}"; valid_username "${NODE_USER[$node]}"
            valid_optional_port "${NODE_PORT[$node]}"; valid_key_file "${NODE_KEY[$node]}"; valid_jump "${NODE_JUMP[$node]}"
        else
            NODE_HOST[$node]= NODE_USER[$node]= NODE_PORT[$node]= NODE_KEY[$node]= NODE_JUMP[$node]=
        fi
        if [[ $node == listener ]]; then peer_ip=$connector_ip local_ip=$listener_ip; else peer_ip=$listener_ip local_ip=$connector_ip; fi
        normalize_allowed_ips "${PLAN[${node}_allowed]}" "$peer_ip" "$local_ip"
        NODE_ALLOWED[$node]=$ALLOWED_IPS PLAN[${node}_allowed]=$ALLOWED_IPS
        NODE_FIREWALL[$node]=${PLAN[${node}_firewall]}; valid_choice "${NODE_FIREWALL[$node]}" 1 2 3 4
    done
    [[ ${NODE_MODE[listener]} != local || ${NODE_MODE[connector]} != local ]]
}

controller() {
    [[ -t 0 ]] || fail "Controller requires an interactive terminal"
    command -v ssh >/dev/null || fail "Install the OpenSSH client on this machine first"
    ui_section 'AmneziaWG 3.1 | Two-server setup'
    ui_hint 'Listener accepts UDP. Connector initiates it. Both sides need SSH/root access.'
    ui_hint "Enter keeps a default; '-' clears an optional field. Ctrl+C saves your progress."
    begin_plan controller
    local endpoint port listener_ip connector_ip node bundle_encoded verified=1 review_status
    while true; do
        if [[ $PLAN_REUSE == 1 ]] && (restore_controller_plan >/dev/null 2>&1); then
            restore_controller_plan
            configuration_table "$listener_ip" "$connector_ip" "$endpoint" "$port"
        else
            collect_controller_plan
        fi
        if approve_plan; then break; else review_status=$?; fi
        [[ $review_status == 2 ]] || return 0
        PLAN_REUSE=0
    done
    CONTROL_DIR=$(mktemp -d /tmp/amnezia-controller.XXXXXXXX)
    trap controller_cleanup EXIT
    REMOTE_SCRIPT=/usr/local/lib/amnezia-site-to-site.sh

    echo "Step 1/5: Check SSH/root access and install the script and tools"
    local listener_identity connector_identity
    for node in listener connector; do
        echo "Checking $node access (SSH/sudo may ask for a password)..."
        exchange_from_node "$node" /etc/machine-id
        if [[ $node == listener ]]; then listener_identity=$EXCHANGE; else connector_identity=$EXCHANGE; fi
    done
    [[ $listener_identity != "$connector_identity" ]] || fail "Both connections point to the same machine; choose two different servers"
    for node in listener connector; do
        upload_script "$node"
        node_command "$node" install
    done
    echo "Step 2/5: Configure listener and securely transfer its AWG 3 bundle"
    node_command listener ensure-listener "$endpoint" "$port" "$listener_ip" "$connector_ip"
    exchange_from_node listener "$STATE/bundle.txt"
    bundle_encoded=$(printf '%s\n' "$EXCHANGE" | base64 -w 0)
    on_node connector "set -e; umask 077; printf '%s' $(shell_quote "$bundle_encoded") | base64 -d > $(shell_quote "$STATE/incoming-bundle.txt")"
    echo "Step 3/5: Configure connector and enroll its public key"
    node_command connector ensure-connector "$STATE/incoming-bundle.txt"
    exchange_from_node connector "$STATE/public.key"
    valid_key "$EXCHANGE"
    node_command listener peer "$EXCHANGE"

    echo "Step 4/5: Prepare host firewalls"
    for node in listener connector; do
        node_notice "$node" "Applying confirmed firewall choice ${NODE_FIREWALL[$node]}"
        case ${NODE_FIREWALL[$node]} in
            1) node_command "$node" firewall firewalld ;;
            2) node_command "$node" firewall ufw ;;
            3) node_command "$node" firewall nft ;;
            4) echo "Allow desired traffic from $INTERFACE; on the listener also allow inbound UDP $port." ;;
            *) fail "Choose 1, 2, 3 or 4" ;;
        esac
    done
    if ! confirm "Are host and provider firewalls ready on both servers"; then
        echo "Configuration saved on both servers. Rerun controller with the same settings to finish."
        return
    fi
    echo "Step 5/5: Start both tunnels and check connectivity"
    node_command listener up
    node_command connector up
    echo "Peer tunnel /32 routes are ready. LAN/default routing remains administrator-managed."
    if ! on_node connector "ping -c 5 -W 2 $(shell_quote "$listener_ip")"; then
        echo "Ping failed. Both configurations are saved. Check UDP access and latest handshake below."
    fi
    node_command listener status
    node_command connector status
    for node in listener connector; do
        if ! node_command "$node" verify; then verified=0; fi
    done
    if [[ $verified == 0 ]]; then
        echo "Configuration completed, but no recent handshake was confirmed on both servers."
        echo "Check the UDP endpoint, provider firewall and service logs, then rerun with the same settings."
        return 1
    fi
    echo "A recent WireGuard handshake is confirmed on both servers."
    echo "To use SSH over the tunnel: ssh -p YOUR_SSH_PORT YOUR_USER@$connector_ip"
    echo "The destination's SSH service must listen on its tunnel IP and its firewall must allow that SSH port."
    admin_notes
}

configure_firewall() {
    if [[ ${1:-} == nft ]]; then
        configure_nft_firewall
        return
    elif [[ ${1:-} == firewalld ]]; then
        configure_firewalld
        return
    fi
    [[ ${1:-} == ufw ]] || fail "Supported automatic firewalls: firewalld, ufw or nft"
    command -v ufw >/dev/null || fail "UFW not installed; use your administrator-managed firewall"
    ufw status | grep -q '^Status: active$' || fail "UFW is inactive; this script will not enable it and risk blocking SSH"
    [[ -f $STATE/role && -f $STATE/settings ]] || fail "Configure the tunnel first"
    local role
    role=$(cat "$STATE/role")
    mapfile -t settings < "$STATE/settings"
    if [[ $role == listener ]]; then
        ufw allow "${settings[3]}/udp" comment "AmneziaWG $INTERFACE"
    fi
    ufw allow in on "$INTERFACE" from "${settings[1]}" comment "AmneziaWG peer $INTERFACE"
    if [[ $role == connector ]]; then
        ufw allow out to any port "${settings[3]}" proto udp comment "AmneziaWG outbound $INTERFACE"
    fi
    echo "Persistent UFW rules added. Provider firewalls still need administrator configuration."
}

configure_nft_firewall() {
    command -v nft >/dev/null && command -v python3 >/dev/null || fail "nft and python3 are required for nftables detection"
    [[ -f $STATE/settings && -f $STATE/role ]] || fail "Configure the tunnel first"
    if command -v ufw >/dev/null && ufw status | grep -q '^Status: active$'; then
        fail "UFW manages this firewall; choose firewall ufw instead"
    fi
    local candidate family table chain firewall_unit
    candidate=$(nft -j list ruleset | python3 -c '
import json, sys
chains = [entry["chain"] for entry in json.load(sys.stdin)["nftables"]
          if "chain" in entry and entry["chain"].get("hook") == "input"
          and entry["chain"]["family"] in ("inet", "ip")]
if len(chains) != 1:
    raise SystemExit("Need exactly one IPv4/inet input base chain; use manual firewall management for this ruleset")
chain = chains[0]
print(chain["family"], chain["table"], chain["name"])
')
    read -r family table chain <<< "$candidate"
    [[ $family == inet || $family == ip ]] || fail "Unsupported nftables family"
    [[ $table =~ ^[a-zA-Z_][a-zA-Z0-9_-]*$ && $chain =~ ^[a-zA-Z_][a-zA-Z0-9_-]*$ ]] || fail "Use manual firewall management for these table/chain names"
    printf '%s\n' "$family" "$table" "$chain" > "$STATE/nft-settings"
    install -d /usr/local/lib
    if [[ $SCRIPT_PATH != /usr/local/lib/amnezia-site-to-site.sh ]]; then
        install -m 700 "$SCRIPT_PATH" /usr/local/lib/amnezia-site-to-site.sh
    fi
    firewall_unit=amnezia-site-firewall-$INTERFACE.service
    cat > "/etc/systemd/system/$firewall_unit" <<EOF
[Unit]
Description=AmneziaWG firewall rules for $INTERFACE
After=nftables.service
Before=$UNIT
PartOf=nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/env AWG_INTERFACE=$INTERFACE bash /usr/local/lib/amnezia-site-to-site.sh firewall-apply
ExecStop=/usr/bin/env AWG_INTERFACE=$INTERFACE bash /usr/local/lib/amnezia-site-to-site.sh firewall-remove

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "/etc/systemd/system/$firewall_unit"
    install -d "/etc/systemd/system/$UNIT.d"
    printf '[Unit]\nRequires=%s\nAfter=%s\n' "$firewall_unit" "$firewall_unit" > "/etc/systemd/system/$UNIT.d/firewall.conf"
    systemctl daemon-reload
    systemctl enable "$firewall_unit"
    systemctl restart "$firewall_unit"
    echo "Rules inserted into $family $table $chain; enabled at boot via $firewall_unit."
    echo "If an external tool reloads nftables directly, restart $firewall_unit afterward."
    [[ $family != ip ]] || echo "These firewall rules allow IPv4 UDP only; use an IPv4 listener endpoint."
}

nft_firewall_rules() {
    local operation=$1 family table chain handle tag
    [[ -f $STATE/nft-settings ]] || fail "No managed nftables settings"
    mapfile -t nft_settings < "$STATE/nft-settings"
    family=${nft_settings[0]} table=${nft_settings[1]} chain=${nft_settings[2]}
    tag=amnezia-site-$INTERFACE
    if ! nft list chain "$family" "$table" "$chain" >/dev/null 2>&1; then
        [[ $operation == remove ]] && return
        fail "Configured nftables input chain is missing; restore your base firewall first"
    fi
    while read -r handle; do
        [[ $handle =~ ^[0-9]+$ ]] || continue
        nft delete rule "$family" "$table" "$chain" handle "$handle"
    done < <(nft -a list chain "$family" "$table" "$chain" | awk -v tag="$tag" 'index($0, "comment \"" tag "\"") {print $NF}')
    [[ $operation != remove ]] || return 0
    mapfile -t settings < "$STATE/settings"
    nft -f - <<EOF
insert rule $family $table $chain iifname "$INTERFACE" ip saddr ${settings[1]} counter accept comment "$tag"
EOF
    if [[ $(cat "$STATE/role") == listener ]]; then
        nft -f - <<EOF
insert rule $family $table $chain udp dport ${settings[3]} counter accept comment "$tag"
EOF
    fi
}

set_paths() {
    [[ $INTERFACE =~ ^[a-zA-Z][a-zA-Z0-9-]{0,14}$ ]] || fail "Invalid interface name"
    STATE=/etc/amnezia/site-to-site/$INTERFACE
    CONFIG_DIR=/etc/amnezia/amneziawg
    CONFIG=$CONFIG_DIR/$INTERFACE.conf
    UNIT=awg-quick@$INTERFACE.service
    SERVICE=/etc/systemd/system/$UNIT.d/site-to-site.conf
    LEGACY_UNIT=amnezia-site-$INTERFACE.service
    LEGACY_SERVICE=/etc/systemd/system/$LEGACY_UNIT
}

ask() {
    local prompt=$1 default=${2:-}
    local -a read_options=(-r)
    [[ ! -t 0 ]] || read_options+=(-e)
    if [[ -n $default ]]; then
        read "${read_options[@]}" -p "  $prompt [$default]: " ANSWER || fail "Input closed; rerun wizard to resume"
        ANSWER=${ANSWER:-$default}
    else
        read "${read_options[@]}" -p "  $prompt: " ANSWER || fail "Input closed; rerun wizard to resume"
    fi
    ANSWER=${ANSWER//$'\e[200~'/}
    ANSWER=${ANSWER//$'\e[201~'/}
    ANSWER=${ANSWER%$'\r'}
}

confirm() {
    ask_validated "$1 (yes/no)" no valid_choice yes y no n
    [[ $ANSWER == yes || $ANSWER == y ]]
}

run_command() {
    printf '\n[local: %s] Action: %s\n' "$(hostname)" "$1" >&2
    AWG_INTERFACE="$INTERFACE" AWG_ALLOWED_IPS="${LOCAL_ALLOWED:-${AWG_ALLOWED_IPS:-}}" bash "$SCRIPT_PATH" "$@"
}

admin_notes() {
    cat <<EOF

Administrator notes
  Interface: $INTERFACE       Service: $UNIT
  Configuration: $CONFIG
  Keys and exchange files: $STATE
  Keep private.key on this server. The bundle contains a shared AWG 3 secret;
  transfer it only to the connector through SSH, never publish it.
  Allow the listener's UDP port in both host and provider firewalls.
  Allow replies to outbound UDP on the connector, and desired local traffic from $INTERFACE.
  Check tunnel IPs against existing routes before configuring either server.
  Table=off: only the peer tunnel /32 route is added explicitly by this service.
  LAN forwarding, return routes and firewall rules require manual administration; NAT is not enabled.
  Troubleshooting: journalctl -u $UNIT -n 50
  Stop and disable: systemctl disable --now $UNIT
EOF
}

verify_tunnel() {
    kernel_interface_check
    local now
    now=$(date +%s)
    if ! awg show "$INTERFACE" latest-handshakes | awk -v now="$now" '$2 > 0 && now - $2 <= 180 {found=1} END {exit !found}'; then
        echo "No recent handshake on $INTERFACE. Check that both services are started and UDP replies are allowed." >&2
        return 1
    fi
    echo "Recent handshake confirmed on $INTERFACE."
}

show_status() {
    echo "Service: $UNIT"
    systemctl is-active "$UNIT" || true
    if ip link show dev "$INTERFACE" >/dev/null 2>&1; then
        awg show "$INTERFACE" public-key
        awg show "$INTERFACE" allowed-ips
        awg show "$INTERFACE" latest-handshakes
        awg show "$INTERFACE" transfer
        ip -brief address show dev "$INTERFACE"
        echo "A started service alone does not confirm connectivity; check the latest handshake and ping."
    else
        echo "Tunnel interface is not running."
    fi
}

wizard() {
    [[ -t 0 ]] || fail "Wizard requires an interactive terminal; use --help for automation commands"
    echo "AmneziaWG site-to-site setup on $(hostname) (this machine)"
    if [[ ${WIZARD_EDIT:-0} == 1 ]]; then PLAN_REUSE=0; else begin_plan wizard; fi
    plan_ask_validated interface "Tunnel interface name" "$INTERFACE" valid_interface
    INTERFACE=$ANSWER
    set_paths
    echo "1) Install, configure and run"
    echo "2) Update AmneziaWG"
    echo "3) Show status"
    echo "4) Exit"
    ask_validated "Choose an action" 1 valid_choice 1 2 3 4
    case $ANSWER in
        1) ;;
        2)
            echo "Updates affect shared binaries/modules, including other tunnels. Plan maintenance."
            if confirm "Proceed with the update"; then
                run_command update
                if [[ -f $SERVICE ]] && run_command kernel-check && confirm "Restart only $UNIT now (brief interruption)"; then
                    systemctl restart "$UNIT"
                    show_status
                fi
            fi
            return
            ;;
        3) show_status; return ;;
        4) return ;;
        *) fail "Choose 1, 2, 3 or 4" ;;
    esac

    local role endpoint port local_ip peer_ip bundle_path= firewall existing=0
    if [[ -f $STATE/role ]]; then
        existing=1
        require_profile
        role=$(cat "$STATE/role")
        [[ $role == listener || $role == connector ]] || fail "Invalid saved server role"
        mapfile -t settings < "$STATE/settings"
        local_ip=${settings[0]} peer_ip=${settings[1]} endpoint=${settings[2]} port=${settings[3]}
        echo "Resuming existing $role configuration. IPs and endpoint are retained."
    else
        echo "1) Listener: public inbound UDP"
        echo "2) Connector: outbound UDP only"
        plan_ask_validated role "Server role" 2 valid_choice 1 2
        case $ANSWER in
            1)
                role=listener
                plan_ask_validated endpoint "Public listener hostname or IPv4 address" "" valid_endpoint; endpoint=$ANSWER
                plan_ask_validated port "UDP listen port" 51830 valid_port; port=$ANSWER
                plan_ask_validated local_ip "This server's tunnel IPv4 address" 10.203.77.1 valid_ip; local_ip=$ANSWER
                plan_ask_validated peer_ip "Connector's tunnel IPv4 address" 10.203.77.2 valid_peer_ip "$local_ip"; peer_ip=$ANSWER
                ;;
            2)
                role=connector
                echo "Copy the confidential AWG 3.1 bundle from the listener through SSH first."
                plan_ask_validated bundle_path "Path to the listener bundle" ./listener-bundle.txt valid_bundle_file; bundle_path=$ANSWER
                [[ -f $bundle_path ]] || fail "Bundle file does not exist"
                mapfile -t bundle < "$bundle_path"
                [[ ${#bundle[@]} -eq 8 && ${bundle[0]} == AWG-SITE-V3 ]] || fail "AWG-SITE-V3 bundle required"
                endpoint=${bundle[1]} port=${bundle[2]} peer_ip=${bundle[3]} local_ip=${bundle[4]}
                valid_key "${bundle[5]}"; valid_key "${bundle[6]}"; valid_key "${bundle[7]}"
                ;;
            *) fail "Choose listener (1) or connector (2)" ;;
        esac
    fi
    [[ $endpoint =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ ]] || fail "Invalid UDP endpoint"
    [[ $port =~ ^[1-9][0-9]{0,4}$ ]] && ((port <= 65535)) || fail "Invalid UDP port"
    valid_ip "$local_ip"; valid_ip "$peer_ip"
    [[ $local_ip != "$peer_ip" ]] || fail "Tunnel IPs must differ"
    local default_allowed=$peer_ip/32
    if [[ $existing == 1 ]]; then
        default_allowed=$(cat "$STATE/allowed-ips" 2>/dev/null || sed -n 's/^AllowedIPs = //p' "$CONFIG")
        default_allowed=${default_allowed:-$peer_ip/32}
    fi
    ui_hint 'AllowedIPs may include /0. Only the peer tunnel /32 route is added; other routes stay manual.'
    plan_ask_validated local_allowed "AllowedIPs on this server (IPv4 CIDRs separated by commas or spaces)" "$default_allowed" valid_wizard_allowed "$peer_ip" "$local_ip"
    normalize_allowed_ips "$ANSWER" "$peer_ip" "$local_ip"
    LOCAL_ALLOWED=$ALLOWED_IPS
    PLAN[local_allowed]=$LOCAL_ALLOWED
    PLAN[local_ip]=$local_ip PLAN[peer_ip]=$peer_ip PLAN[endpoint]=$endpoint PLAN[port]=$port
    if [[ $existing == 1 ]]; then
        AWG_ALLOWED_IPS=$LOCAL_ALLOWED check_saved_allowed_ips
    fi
    ui_section 'Firewall'
    choose_firewall local_firewall; firewall=$ANSWER

    ui_section 'Review local configuration'
    ui_row Server "$(hostname) (this machine)"
    ui_row Role "$role"; ui_row Interface "$INTERFACE"
    ui_row 'Tunnel address' "$local_ip/32"; ui_row 'Peer address' "$peer_ip/32"
    ui_row AllowedIPs "$LOCAL_ALLOWED"; ui_row 'UDP endpoint' "$endpoint:$port"
    ui_row Firewall "$(firewall_label "$firewall")"; ui_row Routing 'Peer /32 automatic; other routes manual'
    ui_hint 'Only this server will change. Configure the other end separately.'
    local review_status
    if approve_plan; then :; else
        review_status=$?
        [[ $review_status != 2 ]] || { WIZARD_EDIT=1 wizard; return; }
        return 0
    fi

    echo "Step 1/4: Install kernel module/tools on $(hostname)"
    run_command install
    echo "Step 2/4: Configure this $role server"
    if [[ $role == listener ]]; then
        run_command ensure-listener "$endpoint" "$port" "$local_ip" "$peer_ip"
    elif [[ $existing == 0 ]]; then
        run_command ensure-connector "$bundle_path"
    fi

    echo "Step 3/4: Exchange public keys and apply confirmed firewall choice"
    if [[ $role == listener ]]; then
        echo "Securely copy this confidential bundle to the connector: $STATE/bundle.txt"
        if [[ ! -f $STATE/peer.key ]]; then
            ask_validated "Paste the connector public key, or press Enter to finish later" "" valid_optional_key
            if [[ -z $ANSWER ]]; then
                echo "Setup saved. Rerun wizard after the connector has generated its public key."
                return
            fi
            run_command peer "$ANSWER"
        fi
    else
        echo "Enroll this public key on the listener:"
        cat "$STATE/public.key"
        if ! confirm "Has the listener enrolled this key"; then
            echo "Setup saved. Rerun wizard after enrollment."
            return
        fi
    fi
    case $firewall in
        1) run_command firewall ufw ;;
        2) run_command firewall nft ;;
        3) echo "Prepare required tunnel traffic and listener UDP $port manually." ;;
    esac
    if ! confirm "Have you checked IP overlaps and prepared host/provider firewalls"; then
        echo "Setup saved. Rerun wizard when the firewall is ready."
        return
    fi

    echo "Step 4/4: Start and enable at boot on $(hostname)"
    if ! confirm "Start $UNIT and enable it at boot"; then return; fi
    run_command up
    show_status
    echo "Start the other server too, then test: ping -c 3 $peer_ip"
    if confirm "Test ping now"; then
        if ! ping -c 3 -W 2 "$peer_ip"; then
            echo "Ping failed: check peer startup, UDP/firewall access, keys and handshake."
        fi
    fi
    admin_notes
}

valid_ip() {
    local address=$1 octet
    local -a octets
    [[ $address =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "Invalid IPv4 address: $address"
    IFS=. read -r -a octets <<< "$address"
    for octet in "${octets[@]}"; do
        [[ $octet == 0 || $octet != 0* ]] || fail "IPv4 octets must not have leading zeros"
        [[ ${#octet} -le 3 ]] && ((10#$octet <= 255)) || fail "Invalid IPv4 address: $address"
    done
}

valid_key() {
    [[ $1 =~ ^[A-Za-z0-9+/]{43}=$ ]] || fail "Invalid public key"
    [[ $(printf '%s' "$1" | base64 -d | wc -c) -eq 32 ]] || fail "Invalid public key length"
}

ipv4_number() {
    local address=$1
    local -a octets
    IFS=. read -r -a octets <<< "$address"
    IP_NUMBER=$(( (10#${octets[0]} << 24) | (10#${octets[1]} << 16) | (10#${octets[2]} << 8) | 10#${octets[3]} ))
}

normalize_allowed_ips() {
    local input=$1 peer_ip=$2 local_ip=$3 cidr address prefix mask network normalized peer_number peer_covered=0 peer_covered_network=0 quoted
    local -a entries
    valid_ip "$peer_ip"; valid_ip "$local_ip"
    ipv4_number "$peer_ip"; peer_number=$IP_NUMBER
    input=${input//,/ }
    read -r -a entries <<< "$input"
    [[ ${#entries[@]} -gt 0 ]] || fail "AllowedIPs must not be empty"
    ALLOWED_IPS=
    for cidr in "${entries[@]}"; do
        printf -v quoted '%q' "$cidr"
        [[ $cidr =~ ^([0-9.]+)/([0-9]{1,2})$ ]] || fail "Invalid CIDR $quoted. Use IPv4/prefix, e.g. 192.168.10.0/24"
        address=${BASH_REMATCH[1]} prefix=${BASH_REMATCH[2]}
        valid_ip "$address"
        [[ $prefix == 0 || $prefix != 0* ]] || fail "CIDR prefix must not have leading zeros"
        ((prefix >= 0 && prefix <= 32)) || fail "AllowedIPs prefix must be 0..32"
        mask=$(( (0xffffffff << (32 - prefix)) & 0xffffffff ))
        ipv4_number "$address"; network=$((IP_NUMBER & mask))
        if (( (peer_number & mask) == network )); then peer_covered=1; fi
        if (( prefix < 32 && (peer_number & mask) == network )); then peer_covered_network=1; fi
        printf -v normalized '%d.%d.%d.%d/%d' "$((network >> 24))" "$(((network >> 16) & 255))" "$(((network >> 8) & 255))" "$((network & 255))" "$prefix"
        [[ ,$ALLOWED_IPS, != *",$normalized,"* ]] || continue
        ALLOWED_IPS+=${ALLOWED_IPS:+,}$normalized
    done
    if [[ $peer_covered_network == 1 ]]; then
        ALLOWED_IPS=,$ALLOWED_IPS,
        ALLOWED_IPS=${ALLOWED_IPS//,$peer_ip\/32,/,}
        ALLOWED_IPS=${ALLOWED_IPS#,}; ALLOWED_IPS=${ALLOWED_IPS%,}
    fi
    [[ $peer_covered == 1 ]] || ALLOWED_IPS+=${ALLOWED_IPS:+,}$peer_ip/32
}


check_saved_allowed_ips() {
    local requested=${AWG_ALLOWED_IPS:-} current
    require_manual_routing
    current=$(sed -n 's/^AllowedIPs = //p' "$CONFIG")
    [[ -n $current || ! -f $STATE/allowed-ips ]] || current=$(cat "$STATE/allowed-ips")
    [[ -n $current ]] || current=${settings[1]}/32
    normalize_allowed_ips "$current" "${settings[1]}" "${settings[0]}"
    current=$ALLOWED_IPS
    normalize_allowed_ips "${requested:-$current}" "${settings[1]}" "${settings[0]}"
    [[ $ALLOWED_IPS == "$current" ]] || fail "Existing AllowedIPs differs from confirmed plan; existing configuration is not overwritten. Use a new interface or coordinate changes on both servers"
}

require_manual_routing() {
    grep -Eq '^[[:space:]]*Table[[:space:]]*=[[:space:]]*off[[:space:]]*$' "$CONFIG" || fail "Existing profile must use Table = off. Stop its service, set Table = off in $CONFIG, configure manual routes, then rerun; existing files are not rewritten automatically"
}

valid_wizard_allowed() {
    normalize_allowed_ips "$1" "$2" "$3"
    if [[ -f $STATE/role ]]; then
        AWG_ALLOWED_IPS=$1 check_saved_allowed_ips
    fi
}

require_profile() {
    [[ -f $STATE/header.key && -f $STATE/preshared.key && -f $STATE/profile && $(cat "$STATE/profile") == AWG-SITE-V3 ]] || fail "Legacy profile: choose a new interface and configure both ends together for AWG 3.1; existing keys/configuration are not overwritten"
}

kernel_check() {
    command -v modprobe >/dev/null || fail "Run install first (modprobe is missing)"
    modprobe amneziawg || fail "Cannot load the kernel module. Check Secure Boot signing, kernel headers and journalctl -k; userspace fallback is disabled"
    local installed loaded
    installed=$(modinfo -F srcversion amneziawg)
    loaded=$(cat /sys/module/amneziawg/srcversion)
    [[ -n $installed && $installed == "$loaded" ]] || fail "Installed and loaded AmneziaWG modules differ. Reboot during maintenance, then rerun; restarting a tunnel alone does not replace the module"
    [[ $(modinfo -F version amneziawg) == 3.1.* ]] || fail "AWG 3.1 kernel module required; run install"
    echo "AWG 3.1 kernel module loaded and matches the installed build."
}

kernel_interface_check() {
    ip -j -d link show dev "$INTERFACE" | python3 -c '
import json, sys
links = json.load(sys.stdin)
if not links or links[0].get("linkinfo", {}).get("info_kind") != "amneziawg":
    raise SystemExit("Expected a kernel AmneziaWG interface; userspace interfaces are refused")
'
}

ensure_kernel_headers() {
    local kernel_release=$1 candidate architecture
    if [[ -f /lib/modules/$kernel_release/build/Makefile ]]; then
        echo "Using existing headers for the running kernel: $kernel_release"
        return
    fi
    candidate=$(apt-cache policy "linux-headers-$kernel_release" | awk '/Candidate:/ {print $2}')
    if [[ -z $candidate || $candidate == '(none)' ]]; then
        echo "Headers for running kernel $kernel_release are not available in your configured APT repositories." >&2
        echo "No kernel upgrade or reboot was performed. Keep provider console access available." >&2
        if [[ $ID == debian ]]; then
            architecture=$(dpkg --print-architecture)
            case $architecture in
                amd64|arm64)
                    echo "For a standard Debian kernel, during maintenance run:" >&2
                    echo "  sudo apt-get install linux-image-$architecture linux-headers-$architecture" >&2
                    echo "  sudo reboot" >&2
                    ;;
                *) echo "Install your architecture's supported kernel and matching headers, then reboot." >&2 ;;
            esac
        else
            echo "Install headers from the kernel's original trusted source, or install a supported Ubuntu kernel and its matching headers, then reboot." >&2
        fi
        fail "Rerun this script after booting the matching kernel. Headers for a different kernel cannot build a module for $kernel_release"
    fi
    apt-get install -y "linux-headers-$kernel_release"
    [[ -f /lib/modules/$kernel_release/build/Makefile ]] || fail "Installed headers do not provide the running kernel's build tree; check the kernel package and /lib/modules/$kernel_release/build"
}

install_tools() {
    local mode=${1:-install}
    [[ -f /etc/os-release ]] || fail "Cannot identify operating system"
    . /etc/os-release
    [[ $ID == debian || $ID == ubuntu ]] || fail "Only Debian and Ubuntu are supported"
    [[ -d /run/systemd/system ]] || fail "A systemd host is required; containers need host-level module administration"
    local kernel_release build_dir module_version source_dir binary revision component source_repo protocol_version
    kernel_release=$(uname -r)
    [[ $kernel_release =~ ^[a-zA-Z0-9._+-]+$ ]] || fail "Invalid kernel release"
    install -d -m 700 "$STATE"
    apt-get update
    ensure_kernel_headers "$kernel_release"
    apt-get install -y ca-certificates curl python3 build-essential dkms kmod iproute2
    build_dir=$(mktemp -d "$STATE/build.XXXXXXXX")
    if [[ $mode == update ]]; then
        for component in kernel tools; do
            if [[ $component == kernel ]]; then
                source_repo=amneziawg-linux-kernel-module
            else
                source_repo=amneziawg-tools
            fi
            curl -fsSL "https://api.github.com/repos/amnezia-vpn/$source_repo/commits/master" -o "$build_dir/$component-commit.json"
            revision=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha"])' "$build_dir/$component-commit.json")
            [[ $revision =~ ^[a-f0-9]{40}$ ]] || fail "Invalid upstream source revision"
            if [[ $component == kernel ]]; then KERNEL_REV=$revision; else TOOLS_REV=$revision; fi
        done
    fi
    module_version=3.1.20260812-${KERNEL_REV:0:12}
    if [[ $mode == install && -f /usr/local/share/amnezia-site-source-versions ]] &&
        grep -Fxq "kernel=$KERNEL_REV" /usr/local/share/amnezia-site-source-versions &&
        grep -Fxq "tools=$TOOLS_REV" /usr/local/share/amnezia-site-source-versions &&
        [[ -x /usr/local/bin/awg && -x /usr/local/bin/awg-quick ]] &&
        dkms status -m amneziawg -v "$module_version" -k "$kernel_release" | grep -q ': installed'; then
        ensure_standard_service
        kernel_check
        return
    fi
    echo "Building AWG 3.1 kernel $KERNEL_REV and tools $TOOLS_REV"
    curl -fsSL "https://codeload.github.com/amnezia-vpn/amneziawg-linux-kernel-module/tar.gz/$KERNEL_REV" -o "$build_dir/kernel.tar.gz"
    curl -fsSL "https://codeload.github.com/amnezia-vpn/amneziawg-tools/tar.gz/$TOOLS_REV" -o "$build_dir/tools.tar.gz"
    tar -xzf "$build_dir/kernel.tar.gz" -C "$build_dir"
    tar -xzf "$build_dir/tools.tar.gz" -C "$build_dir"
    protocol_version=$(sed -n 's/^#define WIREGUARD_VERSION "\(3\.1\.[0-9]*\)"$/\1/p' "$build_dir/amneziawg-linux-kernel-module-$KERNEL_REV/src/version.h")
    [[ $protocol_version =~ ^3\.1\.[0-9]+$ ]] || fail "Upstream is not a supported AWG 3.1 build; review before upgrading"
    module_version=$protocol_version-${KERNEL_REV:0:12}
    source_dir=/usr/src/amneziawg-$module_version
    if [[ ! -d $source_dir ]]; then
        cp -a "$build_dir/amneziawg-linux-kernel-module-$KERNEL_REV/src" "$source_dir"
        cat > "$source_dir/dkms.conf" <<EOF
PACKAGE_NAME="amneziawg"
PACKAGE_VERSION="$module_version"
AUTOINSTALL="yes"
BUILT_MODULE_NAME[0]="amneziawg"
DEST_MODULE_LOCATION[0]="/updates/dkms"
MAKE[0]="make KERNELRELEASE=\$kernelver WIREGUARD_VERSION=$protocol_version"
CLEAN="make clean KERNELRELEASE=\$kernelver"
EOF
    fi
    if [[ -z $(dkms status -m amneziawg -v "$module_version") ]]; then
        dkms add -m amneziawg -v "$module_version"
    fi
    if ! dkms status -m amneziawg -v "$module_version" -k "$kernel_release" | grep -Eq ': (built|installed)'; then
        dkms build -m amneziawg -v "$module_version" -k "$kernel_release"
    fi
    make -C "$build_dir/amneziawg-tools-$TOOLS_REV/src" -j "$(nproc)"
    make -C "$build_dir/amneziawg-tools-$TOOLS_REV/src" install PREFIX=/usr/local DESTDIR="$build_dir/staged" \
        WITH_WGQUICK=yes WITH_SYSTEMDUNITS=no WITH_BASHCOMPLETION=no
    install -d -m 700 "$build_dir/backup"
    for binary in awg awg-quick; do
        if [[ -f /usr/local/bin/$binary ]]; then
            cp -p "/usr/local/bin/$binary" "$build_dir/backup/$binary"
        fi
    done
    modinfo -n amneziawg > "$build_dir/backup/module-path.txt" 2>/dev/null || true
    if [[ -s $build_dir/backup/module-path.txt ]]; then
        cp -p "$(cat "$build_dir/backup/module-path.txt")" "$build_dir/backup/"
    fi
    dkms install --force -m amneziawg -v "$module_version" -k "$kernel_release"
    depmod -a "$kernel_release"
    for binary in awg awg-quick; do
        install -m 755 "$build_dir/staged/usr/local/bin/$binary" "/usr/local/bin/$binary.new"
        mv "/usr/local/bin/$binary.new" "/usr/local/bin/$binary"
    done
    install -d /usr/local/share
    printf '%s\n' "kernel=$KERNEL_REV" "tools=$TOOLS_REV" "dkms=$module_version" > "$build_dir/source-versions.txt"
    install -m 644 "$build_dir/source-versions.txt" /usr/local/share/amnezia-site-source-versions
    echo "Installed DKMS module and tools. Sources, previous binaries/module: $build_dir"
    echo "Existing tunnels were not stopped; obsolete DKMS versions are retained for rollback."
    ensure_standard_service
    kernel_check
}

update_tools() {
    echo "Updating official kernel/tools sources; keys and configuration are retained."
    install_tools update
    echo "No tunnel restarted. After kernel-check succeeds: systemctl restart $UNIT"
}

write_config() {
    local private_key config_tmp header_key
    private_key=$(cat "$STATE/private.key")
    header_key=$(cat "$STATE/header.key")
    config_tmp=$(mktemp "$CONFIG_DIR/$INTERFACE.XXXXXXXX")
    cat > "$config_tmp" <<EOF
[Interface]
PrivateKey = $private_key
Address = $LOCAL_IP/32
Table = off
PostUp = /usr/bin/env AWG_INTERFACE=%i bash /usr/local/lib/amnezia-site-to-site.sh route-peer
ListenPort = $PORT
MTU = 1280
Jc = 0
Jmin = 40
Jmax = 70
S1 = 32
S2 = 32
S3 = 32
S4 = 32
HeaderProtectionKey = $header_key
ContentPaddingAddition = 16-64
RandomTrailers = off
DisableCookies = off
H1 = 1
H2 = 2
H3 = 3
H4 = 4
EOF
    if [[ $ROLE == connector ]]; then
        sed -i 's/^Jc = 0$/Jc = 4/' "$config_tmp"
    fi
    if [[ -n ${PEER_KEY:-} ]]; then
        cat >> "$config_tmp" <<EOF

[Peer]
PublicKey = $PEER_KEY
PresharedKey = $(cat "$STATE/preshared.key")
AdvancedSecurity = on
AllowedIPs = $(cat "$STATE/allowed-ips" 2>/dev/null || printf '%s/32' "$PEER_IP")
EOF
        if [[ $ROLE == connector ]]; then
            printf 'Endpoint = %s:%s\nPersistentKeepalive = 25\n' "$ENDPOINT" "$PORT" >> "$config_tmp"
        fi
    fi
    mv "$config_tmp" "$CONFIG"
}

route_peer() {
    require_profile
    require_manual_routing
    kernel_interface_check
    local local_ip peer_ip existing
    local -a route_settings
    mapfile -t route_settings < "$STATE/settings"
    local_ip=${route_settings[0]} peer_ip=${route_settings[1]}
    valid_ip "$local_ip"; valid_peer_ip "$peer_ip" "$local_ip"
    existing=$(ip -j -4 route show table main exact "$peer_ip/32")
    if [[ $existing != '[]' ]]; then
        printf '%s' "$existing" | python3 -c '
import json, sys
routes = json.load(sys.stdin)
if not routes or any(route.get("dev") != sys.argv[1] or route.get("type", "unicast") != "unicast" or "gateway" in route or route.get("prefsrc", sys.argv[2]) != sys.argv[2] for route in routes):
    raise SystemExit("Conflicting peer /32 route already exists; it was not replaced. Review your main routing table.")
' "$INTERFACE" "$local_ip" || fail "Peer route conflict; existing administrator-managed route was preserved"
        return
    fi
    ip -4 route add "$peer_ip/32" dev "$INTERFACE" src "$local_ip"
    echo "Peer route ready: $peer_ip/32 dev $INTERFACE src $local_ip"
}

ensure_standard_service() {
    systemctl cat awg-quick@.service >/dev/null 2>&1 && return 0
    local temporary name
    temporary=$(mktemp -d "$STATE/systemd.XXXXXXXX")
    for name in wg-quick@.service wg-quick.target; do
        curl -fsSL "https://raw.githubusercontent.com/amnezia-vpn/amneziawg-tools/$TOOLS_REV/src/systemd/$name" -o "$temporary/$name"
    done
    install -d /usr/local/lib/systemd/system
    install -m 644 "$temporary/wg-quick@.service" /usr/local/lib/systemd/system/awg-quick@.service
    install -m 644 "$temporary/wg-quick.target" /usr/local/lib/systemd/system/awg-quick.target
    rm -rf "$temporary"
    systemctl daemon-reload
}

write_service() {
    local quick tools hook temporary
    quick=$(command -v awg-quick)
    tools=$(command -v awg)
    ensure_standard_service
    install -d /etc/systemd/system/"$UNIT.d"
    cat > "$SERVICE" <<EOF
[Service]
Environment=PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=/bin/false
ExecStart=
ExecStart=$quick up %i
ExecStop=
ExecStop=$quick down %i
ExecReload=
ExecReload=/bin/bash -c 'exec $tools syncconf %i <(exec $quick strip %i)'
ExecStartPre=/usr/bin/env AWG_INTERFACE=%i bash /usr/local/lib/amnezia-site-to-site.sh kernel-check
ExecStartPost=/usr/bin/env AWG_INTERFACE=%i bash /usr/local/lib/amnezia-site-to-site.sh kernel-interface-check
EOF
    chmod 644 "$SERVICE"
    if [[ $SCRIPT_PATH != /usr/local/lib/amnezia-site-to-site.sh ]]; then
        install -D -m 700 "$SCRIPT_PATH" /usr/local/lib/amnezia-site-to-site.sh
    fi
    hook='PostUp = /usr/bin/env AWG_INTERFACE=%i bash /usr/local/lib/amnezia-site-to-site.sh route-peer'
    if ! grep -Fxq "$hook" "$CONFIG"; then
        cp -p "$CONFIG" "$STATE/config-before-standard.conf"
        temporary=$(mktemp "$CONFIG_DIR/$INTERFACE.XXXXXXXX")
        awk -v hook="$hook" '{print} /^\[Interface\]$/ {print hook}' "$CONFIG" > "$temporary"
        chmod 600 "$temporary"
        mv "$temporary" "$CONFIG"
    fi
    systemctl daemon-reload
}

migrate_service() {
    [[ -f $LEGACY_SERVICE && -f $CONFIG ]] || fail "No legacy service to migrate"
    require_profile
    require_manual_routing
    kernel_check
    systemctl is-active --quiet "$UNIT" && fail "Standard service is already active; review the legacy service manually"
    write_service
    if [[ -f /etc/systemd/system/$LEGACY_UNIT.d/firewall.conf ]]; then
        install -m 644 /etc/systemd/system/"$LEGACY_UNIT.d/firewall.conf" /etc/systemd/system/"$UNIT.d/firewall.conf"
    fi
    systemctl daemon-reload
    echo "Migrating $LEGACY_UNIT to $UNIT; the tunnel will briefly restart."
    systemctl stop "$LEGACY_UNIT"
    if systemctl enable --now "$UNIT"; then
        systemctl disable "$LEGACY_UNIT"
        mv "$LEGACY_SERVICE" "$STATE/legacy-service.backup"
        if [[ -d /etc/systemd/system/$LEGACY_UNIT.d ]]; then
            mv /etc/systemd/system/"$LEGACY_UNIT.d" "$STATE/legacy-dropins.backup"
        fi
        systemctl daemon-reload
        echo "Migration complete: $UNIT"
    else
        systemctl stop "$UNIT" || true
        systemctl disable "$UNIT" || true
        systemctl start "$LEGACY_UNIT" || fail "Migration failed and legacy restart failed; check the journal"
        fail "Migration failed; legacy service was restarted"
    fi
}

[[ ${1:-} != --help && ${1:-} != -h ]] || { usage; exit 0; }
trap 'error_status=$?; echo "Action failed. Check the message above; completed setup steps are retained. Rerun with the same settings to resume." >&2; exit "$error_status"' ERR
if [[ $# -eq 0 ]]; then
    [[ -t 0 ]] || fail "Interactive setup needs a terminal; use --help for automation commands"
    ui_section 'AmneziaWG 3.1 | Setup'
    ui_hint '1  Two servers from here (SSH controller)'
    ui_hint '2  This server only (local wizard; requires root)'
    ask_validated "Setup mode" 1 valid_choice 1 2
    case $ANSWER in 1) set -- controller ;; 2) set -- wizard ;; *) fail "Choose 1 or 2" ;; esac
fi
if [[ $1 == controller ]]; then
    [[ $# -eq 1 ]] || fail "controller takes no arguments"
    controller
    exit
fi
[[ $EUID -eq 0 ]] || fail "Run with sudo or as root"
[[ ${AWG_UI_ACTION:-} == "$1" ]] || printf '\n[server: %s] %s\n' "$(hostname)" "$1" >&2
set_paths

if [[ $1 == ensure-listener || $1 == ensure-connector ]]; then
    action=${1#ensure-}
    shift
    if [[ -f $STATE/role ]]; then
        [[ $(cat "$STATE/role") == "$action" && -f $CONFIG ]] || fail "Existing configuration has a different role or is incomplete"
        [[ ! -e $LEGACY_SERVICE ]] || fail "Run migrate first to switch the legacy service to $UNIT"
        mapfile -t settings < "$STATE/settings"
        if [[ $action == listener ]]; then
            [[ $# -eq 4 && ${settings[0]} == "$3" && ${settings[1]} == "$4" && ${settings[2]} == "$1" && ${settings[3]} == "$2" ]] || fail "Existing listener settings differ; choose another interface"
        else
            [[ $# -eq 1 && -f $1 ]] || fail "Connector bundle required"
            mapfile -t bundle < "$1"
            [[ ${#bundle[@]} -eq 8 && ${bundle[0]} == AWG-SITE-V3 && ${settings[0]} == "${bundle[4]}" && ${settings[1]} == "${bundle[3]}" && ${settings[2]} == "${bundle[1]}" && ${settings[3]} == "${bundle[2]}" ]] || fail "Existing connector settings differ; choose another interface"
            grep -Fxq "PublicKey = ${bundle[5]}" "$CONFIG" || fail "Existing listener public key differs"
            [[ -f $STATE/header.key && $(cat "$STATE/header.key") == "${bundle[6]}" ]] || fail "Existing AWG 3 header protection key differs"
            [[ -f $STATE/preshared.key && $(cat "$STATE/preshared.key") == "${bundle[7]}" ]] || fail "Existing peer preshared key differs"
        fi
        require_profile
        check_saved_allowed_ips
        echo "Matching $action configuration retained."
        exit
    fi
    set -- "$action" "$@"
fi

    case $1 in
    firewall-apply|firewall-remove)
        [[ $# -eq 1 ]] || fail "$1 takes no arguments"
        firewall_rules "${1#firewall-}"
        ;;
    firewall)
        [[ $# -eq 2 ]] || fail "firewall firewalld|ufw|nft"
        configure_firewall "$2"
        ;;
    wizard)
        [[ $# -eq 1 ]] || fail "wizard takes no arguments"
        wizard
        ;;
    update)
        [[ $# -eq 1 ]] || fail "update takes no arguments"
        update_tools
        ;;
    kernel-check)
        [[ $# -eq 1 ]] || fail "kernel-check takes no arguments"
        kernel_check
        ;;
    kernel-interface-check)
        [[ $# -eq 1 ]] || fail "kernel-interface-check takes no arguments"
        kernel_interface_check
        ;;
    route-peer)
        [[ $# -eq 1 ]] || fail "route-peer takes no arguments"
        route_peer
        ;;
    migrate)
        [[ $# -eq 1 ]] || fail "migrate takes no arguments"
        migrate_service
        ;;
    install)
        [[ $# -eq 1 ]] || fail "install takes no arguments"
        install -d -m 700 "$STATE"
        install_tools
        exit
        ;;
    status)
        [[ $# -eq 1 ]] || fail "status takes no arguments"
        show_status
        exit
        ;;
    verify)
        [[ $# -eq 1 ]] || fail "verify takes no arguments"
        verify_tunnel
        ;;
    listener|connector)
        command -v awg >/dev/null && command -v awg-quick >/dev/null || fail "Run install first"
        kernel_check
        [[ ! -e $CONFIG && ! -e $STATE/role && ! -e $SERVICE && ! -e $LEGACY_SERVICE ]] || fail "Interface already configured; choose another AWG_INTERFACE"
        ip link show dev "$INTERFACE" >/dev/null 2>&1 && fail "Interface already exists"
        ROLE=$1
        if [[ $ROLE == listener ]]; then
            [[ $# -eq 2 || $# -eq 3 || $# -eq 5 ]] || fail "listener ENDPOINT [PORT [LOCAL_IP PEER_IP]]"
            ENDPOINT=$2 PORT=${3:-51830} LOCAL_IP=${4:-10.203.77.1} PEER_IP=${5:-10.203.77.2}
            PEER_KEY=
        else
            [[ $# -eq 2 && -f $2 ]] || fail "connector requires a bundle file"
            mapfile -t bundle < "$2"
            [[ ${#bundle[@]} -eq 8 && ${bundle[0]} == AWG-SITE-V3 ]] || fail "An AWG 3 bundle (AWG-SITE-V3) is required; legacy bundles are not supported"
            ENDPOINT=${bundle[1]} PORT=${bundle[2]} PEER_IP=${bundle[3]} LOCAL_IP=${bundle[4]} PEER_KEY=${bundle[5]}
            valid_key "$PEER_KEY"
            valid_key "${bundle[6]}"
            valid_key "${bundle[7]}"
        fi
        [[ $ENDPOINT =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ ]] || fail "Endpoint must be an IPv4 address or hostname"
        [[ $PORT =~ ^[1-9][0-9]{0,4}$ ]] && ((PORT <= 65535)) || fail "Invalid UDP port"
        valid_ip "$LOCAL_IP"
        valid_ip "$PEER_IP"
        [[ $LOCAL_IP != "$PEER_IP" ]] || fail "Tunnel IPs must differ"
        normalize_allowed_ips "${AWG_ALLOWED_IPS:-$PEER_IP/32}" "$PEER_IP" "$LOCAL_IP"
        if ss -H -lun | awk '{print $4}' | grep -Eq ":$PORT$"; then
            fail "UDP port $PORT is already in use"
        fi
        install -d -m 700 "$STATE" "$CONFIG_DIR"
        if [[ $ROLE == listener ]]; then
            [[ -e $STATE/header.key ]] || awg genkey > "$STATE/header.key"
            [[ -e $STATE/preshared.key ]] || awg genpsk > "$STATE/preshared.key"
        else
            printf '%s\n' "${bundle[6]}" > "$STATE/header.key"
            printf '%s\n' "${bundle[7]}" > "$STATE/preshared.key"
        fi
        [[ -e $STATE/private.key ]] || awg genkey > "$STATE/private.key"
        awg pubkey < "$STATE/private.key" > "$STATE/public.key"
        printf '%s\n' "$ROLE" > "$STATE/role"
        printf '%s\n' AWG-SITE-V3 > "$STATE/profile"
        printf '%s\n' "$LOCAL_IP" "$PEER_IP" "$ENDPOINT" "$PORT" > "$STATE/settings"
        printf '%s\n' "$ALLOWED_IPS" > "$STATE/allowed-ips"
        write_config
        write_service
        if [[ $ROLE == listener ]]; then
            printf 'AWG-SITE-V3\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' "$ENDPOINT" "$PORT" "$LOCAL_IP" "$PEER_IP" "$(cat "$STATE/public.key")" "$(cat "$STATE/header.key")" "$(cat "$STATE/preshared.key")" > "$STATE/bundle.txt"
            echo "AWG 3 configured. Confidential connector bundle: $STATE/bundle.txt"
        else
            cat "$STATE/public.key"
        fi
        ;;
    peer)
        [[ $# -eq 2 ]] || fail "peer requires a public key"
        valid_key "$2"
        [[ -f $STATE/role && $(cat "$STATE/role") == listener ]] || fail "Run listener first"
        require_profile
        if [[ -e $STATE/peer.key ]]; then
            [[ $(cat "$STATE/peer.key") == "$2" ]] || fail "A different peer is already enrolled"
            echo "Matching peer key retained."
            exit
        fi
        if systemctl is-active --quiet "$UNIT" || systemctl is-active --quiet "$LEGACY_UNIT"; then
            fail "Stop the tunnel service before enrolling a peer"
        fi
        ROLE=listener PEER_KEY=$2
        mapfile -t settings < "$STATE/settings"
        LOCAL_IP=${settings[0]} PEER_IP=${settings[1]} ENDPOINT=${settings[2]} PORT=${settings[3]}
        write_config
        printf '%s\n' "$PEER_KEY" > "$STATE/peer.key"
        ;;
    up)
        [[ $# -eq 1 ]] || fail "up takes no arguments"
        [[ -f $CONFIG ]] || fail "Configure listener or connector first"
        [[ ! -e $LEGACY_SERVICE ]] || fail "Run migrate first to switch the legacy service to $UNIT"
        require_profile
        require_manual_routing
        kernel_check
        grep -q '^\[Peer\]$' "$CONFIG" || fail "Enroll the connector public key first"
        grep -q '^HeaderProtectionKey = ' "$CONFIG" || fail "AWG 3 header protection is required; configure a new interface"
        write_service
        systemctl enable --now "$UNIT"
        route_peer
        echo "Started $UNIT. Check status and ping the peer tunnel IP."
        ;;
    *) usage; exit 1 ;;
esac
