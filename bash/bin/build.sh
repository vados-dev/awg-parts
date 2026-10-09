#!/usr/bin/env bash

#########
### BUILD
### собирает модули из src/ в один файл ${dir_name}/module.sh
### порядок папок важен: header первый, entry последний
########################################################

#set -Eeuo pipefail
set -o pipefail

### Переменные:
###############
TOTAL_LINES=0
MISSING=0

#-> порядок сборки: header -> модули -> entry:
DIRS=(
    "00_head"
    "01_info"
    "02_install"
    "03_awg2"
    "04_awg3"
    "06_warp"
    "08_nmcli"
    "15_utils"
    "90_main"
    "99_entry"
)

#SELF="$(readlink -f "${BASH_SOURCE[0]}")"
#-> Новый SELF без файла на конце
SELF="$(dirname $(readlink -f "${BASH_SOURCE[0]}"))"
BUILD_DIR="${SELF}"

#-> Подключаем инклюды
source "${BUILD_DIR}/include/.${BUILD_DIR##*/}-env"
source $colors_inc
source $output_inc

str_replace(){
    local rep_file=$(<$1)
    local rep_str=$2
    local new_str=$3
    rep_file="${rep_file//$rep_str/$new_str}"
    printf "%s\n" "$rep_file"
}

### Сборка меню:
################
# Чтение файла-массива (Items, Actions) → переменная с именем файла
get_arr() {
    local arr_file=$1
    local arr_var="${1##*/}"
    local arr_val=""
    local line
    TOTAL_LINES=$((TOTAL_LINES + 1))
    while IFS= read -r line; do
        arr_val+="\"${line}\" "
    done < "${arr_file}"
    printf -v "${arr_var}" '%s' "${arr_val% }"
}

# Чтение обычного файла (Title, Descr, Type) → переменная с именем файла
get_file() {
    local menu_file=$1
    local menu_var="${1##*/}"
    TOTAL_LINES=$((TOTAL_LINES + 1))
    printf -v "${menu_var}" '%s' "$(<"${menu_file}")"
}

# Сборка одного меню из папки: читает Items, Actions, Title, Descr, Type и генерирует функцию menu_{name} с вызовом show_menu
build_menu() {
    local dir="$1"
    local item
    for item in "$dir"/*; do
        [[ -d "$item" ]] || continue
        [[ "${item##*/}" == "menu" ]] && continue   # на всякий случай
        # Сброс переменных — чтобы от прошлого меню не осталось мусора
        unset Items Actions Title Descr Type
        # Читаем файлы из папки меню
        local f
        for f in "$item"/*; do
            [[ -f "$f" ]] || continue
            case "${f##*/}" in
                Items|Actions) get_arr "$f"  ;;
                *)            get_file "$f" ;;
            esac
        done
        local menu_name="menu_${item##*/}"
        printf "#-> %s:\n" "${Title:-${item##*/}}"
        printf "%s() {\n" "$menu_name"
        printf "    declare mItems=(%s)\n"    "${Items:-}"
        printf "    declare mActions=(%s)\n"  "${Actions:-}"
        printf "    declare mTitle=\"%s\"\n"  "${Title:-}"
        printf "    declare mDescr=\"%s\"\n"  "${Descr:-}"
        printf "    declare mType=\"%s\"\n"   "${Type:-}"
        printf "    show_menu\n}\n\n"
    done
}


### Сборка модулей:
###################
# Сборка модуля: common.sh + module.sh → в MAIN_SCRIPT, подпапка menu/ → build_menu
build_modules() {
    local dir="$1"
    local item
    for item in "$dir"/*; do
        if [ -d "$item" ]; then
            [[ "${item##*/}" == "menu" ]] && build_menu "$item"
        elif [ -f "$item" ]; then
            case "${item##*/}" in
                common.sh|module.sh)
                    local line
                    while IFS= read -r line; do
                        [[ "$line" == "#!/"* ]] && continue
                        if [[ "$line" == "#<::PROJ_WORK_DIR::>" ]]; then
                            printf 'PROJ_WORK_DIR="%s"\n' "${PROJ_WORK_DIR}"
                        else
                            printf '%s\n' "$line"
                        fi
                        ((TOTAL_LINES++))
                    done < "$item"
                    ;;
            esac
        fi
    done
}

cecho sW "Сборка "; cecho sM "${app_name} "; cecho sY "${app_version}"; cecho sW "...\n"

#-> Начинаем с shebang:
printf '#!/usr/bin/env bash\n\n' > "${MAIN_SCRIPT}"
printf '##########################################################\n' >> "${MAIN_SCRIPT}"
printf "### ${pr_descr}\n" >> "${MAIN_SCRIPT}"
printf "#-> ${app_name} ${app_version}\n" >> "${MAIN_SCRIPT}"
printf "#-> Git-Hub: ${github_url}${pr_owner}/${repo_name}/\n" >> "${MAIN_SCRIPT}"
printf "#-> Собран: $(date -u +'%Y-%m-%d %H:%M:%S %Z')\n" >> "${MAIN_SCRIPT}"
printf '##########################################################\n\n' >> "${MAIN_SCRIPT}"

cd ${SRC_DIR}
for d in "${DIRS[@]}"; do
    src="${d}"
    if [[ ! -d "$src" ]]; then
        log_error "Перечисленная папка пропущена: $d (не найдена)!"
        MISSING=$((MISSING + 1))
        continue
    else
        ! build_modules "${d}" "" >> "${MAIN_SCRIPT}" && { log_warn "Модуль ${d} не добавлен."; } || { log_ok "Добавлен модуль: ${d}."; }
    fi
done

#for f in "${FILES[@]}"; do
#    src="${SRC_DIR}/${f}"
#    if [[ ! -f "$src" ]]; then
#        printf "  Пропущен: ${f} (файл не найден)"
#        MISSING=$((MISSING + 1))
#        continue
#    fi
#    lines=$(wc -l < "$src")
#    TOTAL_LINES=$((TOTAL_LINES + lines))
#    echo "" >> "${MAIN_SCRIPT}"
#    echo "# === ${f} ===" >> "${MAIN_SCRIPT}"
#    # - пропускаем shebang из модулей, он уже есть в начале -
#    if head -1 "$src" | grep -q '^#!/'; then
#        tail -n +2 "$src" >> "${MAIN_SCRIPT}"
#    else
#        cat "$src" >> "${MAIN_SCRIPT}"
#    fi
#    echo "  [OK] ${f} (${lines} строк)"
#done

chmod +x "${MAIN_SCRIPT}"

printf '%s\n' "$dashes"
printf "$(cecho Ws 'Готово: ') $(cecho Gs '%s')\n" "${MAIN_SCRIPT}"
printf "$(cecho Ws 'Строк: %s')\n" "${TOTAL_LINES}"
printf "$(cecho Ws 'Модулей: ') $(cecho Gs '%s')\n" "$((${#DIRS[@]} - 2))"
[[ "${MISSING}" -eq 0 ]] > /dev/null 2>&1 || printf "$(cecho Rs 'Пропущено: %s')\n" "${MISSING}"
main_size=$(du -bh "${MAIN_SCRIPT}" | awk '{print $1}')
printf "$(cecho Ws 'Размер: %b')\n" "${main_size}"

exit 0


#                if head -1 "$item" | grep -q '^#!/'; then
#                    $read_item="$(tail -n +2 "$item")"
#                else
#                    $read_item="$item"
#                fi
                #echo "$indent$item/" '^#!/' ""
#for file in `find ./menu/main/ -type f -name "*.*"`; do
#    if [[ "${file##*/}" == "Items.arr" ]]; then
#        Items=()
#        while IFS= read -r line; do
#            item=$(echo \"$line\" | awk '{printf "%s ", $0}')
#            Items+="$item"
#        done < "${file}"
#        printf "    declare mItems=(%s)\n" "${Items% }"
#    elif [[ "${file##*/}" == "Actions.arr" ]]; then
#        Actions=()
#        while IFS= read -r line; do
#            action=$(echo \"$line\" | awk '{printf "%s ", $0}')
#            Actions+="$action"
#        done < "${file}"
#        printf "    declare mActions=(%s)\n" "${Actions% }"
#    elif [[ "${file##*/}" == "Title.txt" ]]; then
#        Title=$(<${file})
#        printf "    declare mTitle=\"%s\"\n" "${Title}"
#    elif [[ "${file##*/}" == "Descr.txt" ]]; then
#        Descr=$(<${file})
#        printf "    declare mDescr=\"%s\"\n" "${Descr}"
#    elif [[ "${file##*/}" == "Type.txt" ]]; then
#        Type=$(<${file})
#        printf "    declare mType=\"%s\"\n" "${Type}"
#    fi
#done >> "$MAIN_SCRIPT"
#exit 0
#for dir in */; do
#    echo "Сборка из папки dir: $dir"
#    if [[ "$dir" == "menu/" ]]; then
#        for menu in */menu; do
#            echo "Сборка из папки menu: $menu"
#            if [[ "$menu" != "" ]]; then
#                names=$(ls ${menu%/*})
#                echo "Сборка из папки names: $names"
#
#                for menu_name in */menu/*; do
#                    menu_name=$(dir ${menu}/*)
#                    echo $menu_name
#                done
#            fi
#        done
#    fi
# > "$dir/build.txt"
#done
#exit 0
#find ./ -type f | xargs bash -c '
#    echo "Обрабатываю: $0";
#    cat "$0"'; {} \;
#clear
#find_read() {
#    local dir="$1"
#    local pattern="$2"
#    find "$dir" -type f \( -name "$pattern" -o -path "*.git*" \) -print0 | while IFS= read -r -d '' file; do
#        echo "Чтение файла: $file"
#        cat "$file"
#    done
#}
#find_read "./menu/main" "*"
#find ./menu/main -type f -name "*" | while read -r file; do
#    cat "$file" > ./out.txt
#done

#add_menu_files() {
#    local dir="$1"
#    local pattern="$2"
#    get_arr() {
#        local arr_file=$1
#        local arr_var="${1##*/}"
#        local arr_val=()
#        TOTAL_LINES=$((TOTAL_LINES + 1))
#        while IFS= read -r line; do
#            item=$(echo \"$line\" | awk '{printf "%s ", $0}')
#            arr_val+="$item"
#            done < "${arr_file}"
#            printf -v ${arr_var} "%s" "${arr_val% }"
#    }
#    get_file() {
#        local menu_file=$1
#        local menu_var="${1##*/}"
#        local menu_val
#        lines=$(wc -l < "${file}")
#        TOTAL_LINES=$((TOTAL_LINES + lines))
#        menu_val=$(<${menu_file})
#        printf -v ${menu_var} "%s" "${menu_val}"
#    }
##    for file in `find $dir -type f -name "$pattern" | sort`; do
#    for file in "$dir"/*; do
#        [[ -f "$file" ]] || continue
#        if [[ ! -f "${file}" ]]; then
#            log_warn "  Пропущен: ${file} (файл не найден)"
#            MISSING=$((MISSING + 1))
#            continue
#        elif [[ "${file##*/}" == "Items" ]]; then
#            get_arr "${file}"
#        elif [[ "${file##*/}" == "Actions" ]]; then
#            get_arr "${file}"
#        else
#            get_file "${file}"
#        fi
#    done
#}

#build_menu() {
#    local dir="$1"
#    local indent="$2"
#    local menu_folder=""
#    for item in "$dir"/*; do
#        if [ -d "$item" ]; then
#            if [[ "${item##*/}" == "menu" ]]; then
#                ! build_menu "$item" "$indent" >> "${MAIN_SCRIPT}" > /dev/null 2>&1 && log_warn "Меню ${d} не добавлено." || log_ok "Добавлено меню: ${d}."
#            else
#                TOTAL_LINES=$((TOTAL_LINES + 3))
#                menu_name="menu_${item##*/}"
#                menu_folder=$indent$item
#                add_menu_files "${menu_folder}" "*"
#                printf "#-> %s:\n" "$Title"
#                printf "%s() {\n" "$menu_name"
#                printf "    declare mItems=(%s)\n" "${Items}"
#                printf "    declare mActions=(%s)\n" "${Actions}"
#                printf "    declare mTitle=\"%s\"\n" "${Title}"
#                printf "    declare mDescr=\"%s\"\n" "${Descr}"
#                printf "    declare mType=\"%s\"\n" "${Type}"
#                printf "    show_menu\n}\n\n"
#            fi
#        fi
#    done
#}

#build_modules() {
#    local dir="$1"
#    local indent="$2"
#    local read_item="" lines=0
#    for item in "$dir"/*; do
#        if [ -d "$item" ]; then
#            if [[ "${item##*/}" != "menu" ]]; then
#                build_modules "$item" "$indent"
#            else
#                build_menu "$item" "$indent"
#            fi
#        elif [ -f "$item" ]; then
#            if [[ "${item##*/}" == "common.sh" || "${item##*/}" == "module.sh" ]]; then
#                while IFS= read -r line; do
#                    #-> Пропускаем shebang из модулей, он уже есть в начале:
#                    if [[ "$line" != "#!/"* ]]; then
#                        #-> Заменяем #<::PROJ_WORK_DIR::> на реальную переменную:
#                        if [[ "$line" == "#<::PROJ_WORK_DIR::>" ]]; then
#                            printf "PROJ_WORK_DIR=\"%s\"\n" "${PROJ_WORK_DIR}"
#                        else
#                            printf "%s\n" "$line"
#                        fi
#                        ((lines++))
#                    fi
#                done < "$item"
#                TOTAL_LINES=$((TOTAL_LINES + lines))
#            fi
#        fi
#    done
#}
