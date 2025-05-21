#!/bin/sh


trace_pipe_path="/sys/kernel/debug/tracing/trace_pipe"


current_uid=$(id -u)


[ "${current_uid}" -ne 0 ] && \
    {
        echo "Must run as root user"
        exit 1
    }


test -f "${trace_pipe_path}" && \
    {
        echo "Reading from trace pipe '${trace_pipe_path}' ..."
        echo ""
        cat "${trace_pipe_path}"
    } || \
    echo "No trace pipe at ${trace_pipe_path}"