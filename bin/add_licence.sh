#!/bin/bash

# SPDX-License-Identifier: GPL-3.0-or-later
# AMEBA - A Minimal eBPF-based Audit: an eBPF-based Linux telemetry collection tool.
# Copyright (C) 2025  Hassaan Irshad
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


script_name="$(basename ${0})"
project_home_path="$(cd "$( dirname "${BASH_SOURCE[0]}" )"/../ && pwd)"


dir_path_src="${project_home_path}/src"
dir_path_bin="${project_home_path}/bin"


license_spdx_id="SPDX-License-Identifier: GPL-3.0-or-later"
read -r -d '' license_text <<'EOF'
AMEBA - A Minimal eBPF-based Audit: an eBPF-based Linux telemetry collection tool.
Copyright (C) 2025  Hassaan Irshad

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
EOF


add_license_to_c_h() {
    local file_path="$1"

    grep -q "${license_spdx_id}" "$file_path" && return

    tmp_file=$(mktemp)
    {
        echo "// ${license_spdx_id}"
        echo "/*"
        echo "${license_text}"
        echo "*/"
        echo ""
        cat "${file_path}"
    } > "${tmp_file}"

    cat "${tmp_file}" > "${file_path}"
    rm "${tmp_file}"
}


add_license_to_script_like() {
    local file_path="$1"

    grep -q "${license_spdx_id}" "$file_path" && return

    tmp_file=$(mktemp)
    if head -n 1 "${file_path}" | grep -q '^#!'; then
        {
            head -n 1 "${file_path}"
            echo ""
            echo "# ${license_spdx_id}"
            echo "${license_text}" | sed "s/^/# /"
            echo ""
            tail -n +2 "${file_path}"
        } > "${tmp_file}"
    else
        {
            echo "# ${license_spdx_id}"
            echo "${license_text}" | sed "s/^/# /"
            echo ""
            cat "${file_path}"
        } > "${tmp_file}"
    fi

    cat "${tmp_file}" > "${file_path}"
    rm "${tmp_file}"
}


update_c_h() {
    while IFS= read -r file_path; do
        add_license_to_c_h "${file_path}"
    done < <(find "${dir_path_src}" -type f \( -name "*.c" -o -name "*.h" \))
}


update_script_like() {
    while IFS= read -r file_path; do
        add_license_to_script_like "${file_path}"
    done < <(find "${dir_path_bin}" -type f \( -name "*.sh" -o -name "*.py" \))
}


update_select_files() {
    while IFS= read -r file_path; do
        add_license_to_script_like "${file_path}"
    done < <(find "${project_home_path}" -type f \( -name 'Makefile' \))
}


main() {
    update_c_h
    update_script_like
    update_select_files
}


main