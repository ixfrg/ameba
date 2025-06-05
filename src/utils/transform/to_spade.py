#!/usr/bin/python3


import argparse
import json


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


buffer = []


def get_spade_record_namespace_clone(
    las_event_id, las_time,
    r_ale, r_cred, r_new_process, r_namespace
):
    if not r_ale:
        return
    # if not r_cred or not r_new_process or not r_namespace:
    if not r_namespace:
        return
    
    operation = None

    sys_id = r_namespace["sys_id"]
    if sys_id == "clone":
        operation = "NEWPROCESS"
    elif sys_id == "setns":
        operation = "SETNS"
    elif sys_id == "unshare":
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


def find_and_remove_record(record_type, task_ctx_id):
    result = None
    collected_buffer = []
    while len(buffer) > 0:
        r = buffer.pop()
        if r["record_type"] == record_type:
            if r["task_ctx_id"] == task_ctx_id:
                result = r
                break
        collected_buffer.append(r)
    for c in collected_buffer:
        buffer.append(c)
    return result


def process_record_audit_log_exit_for_clone(
    json_obj,
    las_event_id,
    las_time,
    task_ctx_id
):
    r_cred = find_and_remove_record(RecordType.CRED, task_ctx_id)
    r_namespace = find_and_remove_record(RecordType.NAMESPACE, task_ctx_id)
    r_new_process = find_and_remove_record(RecordType.NEW_PROCESS, task_ctx_id)
    
    r_spade = get_spade_record_namespace_clone(
        las_event_id, las_time,
        json_obj, r_cred, r_new_process, r_namespace
    )
    print(r_spade)


def process_record_audit_log_exit(json_obj):
    syscall = json_obj["syscall_number"]
    pid = json_obj["pid"]
    las_event_id = json_obj["las_audit"]["event_id"]
    las_time = json_obj["las_audit"]["time"]
    task_ctx_id = json_obj["task_ctx_id"]
    event_id = json_obj["event_id"]

    if len(buffer) == 0:
        # discard
        return

    if syscall == SysNum.CLONE:
        process_record_audit_log_exit_for_clone(
            json_obj, las_event_id, las_time, task_ctx_id
        )
    pass


def process_line(line):
    json_obj = json.loads(line)

    record_type = json_obj["record_type"]

    if record_type == RecordType.AUDIT_LOG_EXIT:
        process_record_audit_log_exit(json_obj)
    else:
        buffer.append(json_obj)


def process_file(file_path):
    try:
        with open(file_path, 'r') as f:
            for line in f.readlines():
                process_line(line.strip())
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
    except Exception as e:
        print(f"Error reading file: {e}")


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