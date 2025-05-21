#!/bin/sh


prov_log_path="/tmp/current_ameba_log.json"


current_uid=$(id -u)


[ "${current_uid}" -ne 0 ] && \
    {
        echo "Must run as root user"
        exit 1
    }


test -f "${prov_log_path}" && \
    {
        echo "Reading from prov log '${prov_log_path}' ..."
        echo ""
        less "${prov_log_path}"
    } || \
    echo "No prov log at ${prov_log_path}"