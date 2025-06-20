#!/usr/bin/python3

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



import argparse
import json


###


BUFFER_WINDOW = 50


###


class RecordType():
    NEW_PROCESS = 1
    CRED = 2
    NAMESPACE = 3
    CONNECT = 4
    ACCEPT = 5
    SEND_RECV = 6
    BIND = 7
    KILL = 8
    AUDIT_LOG_EXIT = 9


class SysId():
    FORK = 1
    VFORK = 2
    CLONE = 3
    SETNS = 4
    UNSHARE = 5
    SENDTO = 6
    SENDMSG = 7
    RECVFROM = 8
    RECVMSG = 9
    ACCEPT = 10
    ACCEPT4 = 11


class SysNum():

    CLONE = 220
    SETNS = 268
    UNSHARE = 97
    CLONE3 = 435
    SENDTO = 206
    SENDMSG = 211
    RECVFROM = 207
    RECVMSG = 212
    ACCEPT = 202
    ACCEPT4 = 242
    BIND = 200
    CONNECT = 203
    KILL = 129


###


buffer = []
"""
--- proc_infos
pid: {
    NEW_PROCESS: {},
    CRED: {}
}
"""
proc_infos = {}


##


def proc_infos_set(r):
    r_type = get_record_type(r)
    r_pid = must_get_value(r, "pid")
    if r_pid not in proc_infos:
        proc_infos[r_pid] = {}
    proc_infos[r_pid][r_type] = r


###


def buffer_append(item):
    buffer.append(item)


def buffer_is_window_full():
    return len(buffer) >= BUFFER_WINDOW


def buffer_is_empty():
    return len(buffer) == 0


def buffer_remove(index):
    item = buffer[index]
    del buffer[index]
    return item


def buffer_get_next_record(task_ctx_id, record_type):
    i = 0

    while i < len(buffer):
        r = buffer[i]
        r_task_ctx_id = get_task_ctx_id(r)
        if r_task_ctx_id == task_ctx_id:
            r_type = get_record_type(r)
            if r_type == record_type:
                return i, r
            # else:
            #     return -1, None
        i += 1
    
    return -1, None


###


def must_get_value(record, key):
    if not isinstance(record, (dict,)):
        raise RuntimeError("Record is not an object") 
    event_id = record["event_id"] if "event_id" in record else None
    if key not in record:
        if event_id is not None:
            raise RuntimeError(f"Missing key '{key}' in record with event id: {event_id}")
        else:
            raise RuntimeError(f"Missing key '{key}' in record without event id: {record}")
    return record[key]


def get_event_id(record):
    return must_get_value(record, "event_id")


def get_record_type(record):
    return must_get_value(record, "record_type")


def is_record_of_type(record, type):
    return get_record_type(record) == type


def get_task_ctx_id(record):
    return must_get_value(record, "task_ctx_id")


def get_syscall_number(record):
    return must_get_value(record, "syscall_number")


def is_task_ctx_id_equal(r1, r2):
    return get_task_ctx_id(r1) == get_task_ctx_id(r2)


def get_las_event_id_and_time(r):
    las_audit = must_get_value(r, "las_audit")
    event_id = must_get_value(las_audit, "event_id")
    time = must_get_value(las_audit, "time")
    return (event_id, time)


###


def get_spade_record_namespace(
    r_ale, r_namespace
):
    las_event_id, las_time = get_las_event_id_and_time(r_ale)
    
    operation = None

    sys_id = r_namespace["sys_id"]
    if sys_id == SysId.CLONE:
        operation = "NEWPROCESS"
    elif sys_id == SysId.SETNS:
        operation = "SETNS"
    elif sys_id == SysId.UNSHARE:
        operation = "UNSHARE"

    syscall = r_ale["syscall_number"]
    ns_ns_pid = r_ale["exit"]
    ns_host_pid = r_namespace["pid"]
    ns_inum_mnt = r_namespace["ns_mnt"]
    ns_inum_net = r_namespace["ns_net"]
    ns_inum_pid = r_namespace["ns_pid"]
    ns_inum_pid_children = r_namespace["ns_pid_children"]
    ns_inum_usr = r_namespace["ns_usr"]
    ns_inum_ipc = r_namespace["ns_ipc"]

    result = f"type=USER msg=audit({las_time}:{las_event_id}):"
    result += f" ns_syscall={syscall}"
    result += f" ns_subtype=ns_namespaces"
    result += f" ns_operation=ns_{operation}"
    result += f" ns_ns_pid={ns_ns_pid}"
    result += f" ns_host_pid={ns_host_pid}"
    result += f" ns_inum_mnt={ns_inum_mnt}"
    result += f" ns_inum_net={ns_inum_net}"
    result += f" ns_inum_pid={ns_inum_pid}"
    result += f" ns_inum_pid_children={ns_inum_pid_children}"
    result += f" ns_inum_usr={ns_inum_usr}"
    result += f" ns_inum_ipc={ns_inum_ipc}"
    return result


def get_proc_info_for_spade_record(pid):
    record_str = ""
    if pid not in proc_infos:
        return record_str
    if RecordType.CRED in proc_infos[pid]:
        cred_obj = proc_infos[pid][RecordType.CRED]
        record_str += f" uid={cred_obj["uid"]}"
        record_str += f" euid={cred_obj["euid"]}"
        record_str += f" suid={cred_obj["suid"]}"
        record_str += f" fsuid={cred_obj["fsuid"]}"
        record_str += f" gid={cred_obj["gid"]}"
        record_str += f" egid={cred_obj["egid"]}"
        record_str += f" sgid={cred_obj["sgid"]}"
        record_str += f" fsgid={cred_obj["fsgid"]}"
    if RecordType.NEW_PROCESS in proc_infos[pid]:
        new_proc_obj = proc_infos[pid][RecordType.NEW_PROCESS]
        record_str += f" ppid={new_proc_obj["ppid"]}"
        comm = new_proc_obj["comm"]
        comm = comm.encode('ascii').hex()
        record_str += f" comm={comm}"
    return record_str


def get_spade_record_netio_intercepted(
    task_ctx_id,
    las_time, las_event_id,
    syscall, exit_val, success, fd, pid,
    # ppid, uid, euid, suid, fsuid, gid, egid, sgid, fsgid, comm,
    sock_type, local_saddr, remote_saddr, remote_saddr_size, net_ns_inum
):
    result = f"type=USER msg=audit({las_time}:{las_event_id}):"
    result += f" netio_intercepted="
    result += "\""
    result += f"syscall={syscall}"
    result += f" exit={exit_val}"
    result += f" success={success}"
    result += f" fd={fd}"
    result += f" pid={pid}"
    result += get_proc_info_for_spade_record(pid)
    # result += f" ppid={ppid}"
    # result += f" uid={uid}"
    # result += f" euid={euid}"
    # result += f" suid={suid}"
    # result += f" fsuid={fsuid}"
    # result += f" gid={gid}"
    # result += f" egid={egid}"
    # result += f" sgid={sgid}"
    # result += f" fsgid={fsgid}"
    # result += f" comm={comm}"
    result += f" socktype={sock_type}"
    result += f" local_saddr={local_saddr}"
    result += f" remote_saddr={remote_saddr}"
    result += f" remote_saddr_size={remote_saddr_size}"
    result += f" net_ns_inum={net_ns_inum}"
    result += f"\""
    return result


def get_spade_record_bind(
    r_ale, r_bind
):
    las_event_id, las_time = get_las_event_id_and_time(r_ale)

    syscall = r_ale["syscall_number"]
    pid = r_bind["pid"]
    fd = r_bind["fd"]
    exit_val = r_ale["exit"]
    success = 1
    sock_type = r_bind["sock_type"]
    local_saddr = r_bind["local"]["sockaddr"]
    remote_saddr = ""
    remote_saddr_size = r_bind["local"]["sockaddr_len"]
    net_ns_inum = r_bind["ns_net"]

    result = get_spade_record_netio_intercepted(
        get_task_ctx_id(r_bind),
        las_time, las_event_id,
        syscall, exit_val, success, fd, pid,
        # ppid, uid, euid, suid, fsuid, gid, egid, sgid, fsgid, comm,
        sock_type, local_saddr, remote_saddr, remote_saddr_size, net_ns_inum
    )

    return result


def get_spade_record_send_recv(
    r_ale, r_send_recv
):
    las_event_id, las_time = get_las_event_id_and_time(r_ale)

    syscall = r_ale["syscall_number"]
    pid = r_send_recv["pid"]
    fd = r_send_recv["fd"]
    exit_val = r_ale["exit"]
    success = 1
    sock_type = r_send_recv["sock_type"]
    local_saddr = r_send_recv["local"]["sockaddr"]
    remote_saddr = r_send_recv["remote"]["sockaddr"]
    remote_saddr_size = r_send_recv["local"]["sockaddr_len"]
    net_ns_inum = r_send_recv["ns_net"]

    result = get_spade_record_netio_intercepted(
        get_task_ctx_id(r_send_recv),
        las_time, las_event_id,
        syscall, exit_val, success, fd, pid,
        # ppid, uid, euid, suid, fsuid, gid, egid, sgid, fsgid, comm,
        sock_type, local_saddr, remote_saddr, remote_saddr_size, net_ns_inum
    )

    return result


def get_spade_record_connect(
    r_ale, r_connect
):
    las_event_id, las_time = get_las_event_id_and_time(r_ale)

    syscall = r_ale["syscall_number"]
    pid = r_connect["pid"]
    fd = r_connect["fd"]
    exit_val = r_ale["exit"]
    success = 1
    sock_type = r_connect["sock_type"]
    local_saddr = r_connect["local"]["sockaddr"]
    remote_saddr = r_connect["remote"]["sockaddr"]
    remote_saddr_size = r_connect["local"]["sockaddr_len"]
    net_ns_inum = r_connect["ns_net"]

    result = get_spade_record_netio_intercepted(
        get_task_ctx_id(r_connect),
        las_time, las_event_id,
        syscall, exit_val, success, fd, pid,
        # ppid, uid, euid, suid, fsuid, gid, egid, sgid, fsgid, comm,
        sock_type, local_saddr, remote_saddr, remote_saddr_size, net_ns_inum
    )

    return result


def get_spade_record_accept(
    r_ale, r_accept
):
    las_event_id, las_time = get_las_event_id_and_time(r_ale)

    syscall = r_ale["syscall_number"]
    pid = r_accept["pid"]
    fd = r_accept["fd"]
    exit_val = r_ale["exit"]
    success = 1
    sock_type = r_accept["sock_type"]
    local_saddr = r_accept["local"]["sockaddr"]
    remote_saddr = r_accept["remote"]["sockaddr"]
    remote_saddr_size = r_accept["local"]["sockaddr_len"]
    net_ns_inum = r_accept["ns_net"]

    result = get_spade_record_netio_intercepted(
        get_task_ctx_id(r_accept),
        las_time, las_event_id,
        syscall, exit_val, success, fd, pid,
        # ppid, uid, euid, suid, fsuid, gid, egid, sgid, fsgid, comm,
        sock_type, local_saddr, remote_saddr, remote_saddr_size, net_ns_inum
    )
    return result


def long_to_hex_str(v):
    if v == 0:
        return "0"
    return v.to_bytes(4, byteorder='big', signed=True).hex().lstrip('0')


def get_spade_record_kill(
    r_ale, r_kill
):
    las_event_id, las_time = get_las_event_id_and_time(r_ale)

    syscall = r_ale["syscall_number"]
    exit_val = r_ale["exit"]
    success = "yes" if exit_val == 0 else "no"
    a0 = r_kill["target_pid"]
    a1 = r_kill["sig"]
    a2 = 0
    a3 = 0
    items = 0
    pid = r_kill["acting_pid"]

    a0 = long_to_hex_str(a0)
    a1 = long_to_hex_str(a1)
    a2 = long_to_hex_str(a2)
    a3 = long_to_hex_str(a3)

    result = f"type=USER msg=audit({las_time}:{las_event_id}):"
    result += f" ubsi_intercepted="
    result += "\""
    result += f"syscall={syscall}"
    result += f" success={success}"
    result += f" exit={exit_val}"
    result += f" a0={a0}"
    result += f" a1={a1}"
    result += f" a2={a2}"
    result += f" a3={a3}"
    result += f" items={items}"
    result += f" pid={pid}"
    result += get_proc_info_for_spade_record(pid)
    result += f"\""
    return result


def process_buffer():
    r1 = buffer_remove(0)
    r1_type = get_record_type(r1)
    r1_task_ctx_id = get_task_ctx_id(r1)

    r2_index = -1
    r2 = None

    spade_record = None

    if r1_type == RecordType.AUDIT_LOG_EXIT:
        syscall_number = get_syscall_number(r1)
        if syscall_number in [SysNum.SETNS, SysNum.UNSHARE, SysNum.CLONE, SysNum.CLONE3]:
            r2_index, r2 = buffer_get_next_record(r1_task_ctx_id, RecordType.NAMESPACE)
            if r2 is not None:
                spade_record = get_spade_record_namespace(r1, r2)
        elif syscall_number in [SysNum.BIND]:
            r2_index, r2 = buffer_get_next_record(r1_task_ctx_id, RecordType.BIND)
            if r2 is not None:
                spade_record = get_spade_record_bind(r1, r2)
        elif syscall_number in [SysNum.SENDTO, SysNum.SENDMSG, SysNum.RECVFROM, SysNum.RECVMSG]:
            r2_index, r2 = buffer_get_next_record(r1_task_ctx_id, RecordType.SEND_RECV)
            if r2 is not None:
                spade_record = get_spade_record_send_recv(r1, r2)
        elif syscall_number in [SysNum.CONNECT]:
            r2_index, r2 = buffer_get_next_record(r1_task_ctx_id, RecordType.CONNECT)
            if r2 is not None:
                spade_record = get_spade_record_connect(r1, r2)
        elif syscall_number in [SysNum.ACCEPT, SysNum.ACCEPT4]:
            r2_index, r2 = buffer_get_next_record(r1_task_ctx_id, RecordType.ACCEPT)
            if r2 is not None:
                spade_record = get_spade_record_accept(r1, r2)
        elif syscall_number in [SysNum.KILL]:
            r2_index, r2 = buffer_get_next_record(r1_task_ctx_id, RecordType.KILL)
            if r2 is not None:
                spade_record = get_spade_record_kill(r1, r2)
        else:
            # Other syscalls
            pass
    elif r1_type == RecordType.NAMESPACE:
        r2_index, r2 = buffer_get_next_record(r1_task_ctx_id, RecordType.AUDIT_LOG_EXIT)
        if r2 is not None:
            syscall_number = get_syscall_number(r2)
            if syscall_number in [SysNum.SETNS, SysNum.UNSHARE, SysNum.CLONE, SysNum.CLONE3]:
                spade_record = get_spade_record_namespace(r2, r1)
    elif r1_type == RecordType.BIND:
        r2_index, r2 = buffer_get_next_record(r1_task_ctx_id, RecordType.AUDIT_LOG_EXIT)
        if r2 is not None:
            syscall_number = get_syscall_number(r2)
            if syscall_number in [SysNum.BIND]:
                spade_record = get_spade_record_bind(r2, r1)
    elif r1_type == RecordType.SEND_RECV:
        r2_index, r2 = buffer_get_next_record(r1_task_ctx_id, RecordType.AUDIT_LOG_EXIT)
        if r2 is not None:
            syscall_number = get_syscall_number(r2)
            if syscall_number in [SysNum.SENDTO, SysNum.SENDMSG, SysNum.RECVFROM, SysNum.RECVMSG]:
                spade_record = get_spade_record_send_recv(r2, r1)
    elif r1_type == RecordType.CONNECT:
        r2_index, r2 = buffer_get_next_record(r1_task_ctx_id, RecordType.AUDIT_LOG_EXIT)
        if r2 is not None:
            syscall_number = get_syscall_number(r2)
            if syscall_number in [SysNum.CONNECT]:
                spade_record = get_spade_record_connect(r2, r1)
    elif r1_type == RecordType.ACCEPT:
        r2_index, r2 = buffer_get_next_record(r1_task_ctx_id, RecordType.AUDIT_LOG_EXIT)
        if r2 is not None:
            syscall_number = get_syscall_number(r2)
            if syscall_number in [SysNum.ACCEPT, SysNum.ACCEPT4]:
                spade_record = get_spade_record_accept(r2, r1)
    elif r1_type == RecordType.KILL:
        r2_index, r2 = buffer_get_next_record(r1_task_ctx_id, RecordType.AUDIT_LOG_EXIT)
        if r2 is not None:
            syscall_number = get_syscall_number(r2)
            if syscall_number in [SysNum.KILL]:
                spade_record = get_spade_record_kill(r2, r1)
    elif r1_type in [RecordType.CRED, RecordType.NEW_PROCESS]:
        proc_infos_set(r1)
    else:
        pass

    if spade_record is not None:
        print(spade_record)

    if r2_index > -1:
        buffer_remove(r2_index)


def process_line(line):
    json_obj = json.loads(line)
    buffer_append(json_obj)
    if buffer_is_window_full():
        process_buffer()


def process_file(file_path):
    try:
        with open(file_path, 'r') as f:
            for line in f.readlines():
                process_line(line.strip())
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
    except Exception as e:
        print(f"Error reading file: {e}")

    while True:
        if buffer_is_empty():
            break
        process_buffer()


def parse_args():
    parser = argparse.ArgumentParser(description='Process a file')
    parser.add_argument('-f', '--file', help='Input file path')
    
    args = parser.parse_args()
    return args
    
    
def main():
    args = parse_args()
    process_file(args.file)


if __name__ == '__main__':
    main()