#pragma once

#include "common/types.h"


long output_record_cred(struct record_cred *ptr);
long output_record_namespace(struct record_namespace *ptr);
long output_record_new_process(struct record_new_process *ptr);
long output_record_accept(struct record_accept *ptr);
long output_record_bind(struct record_bind *ptr);
long output_record_kill(struct record_kill *ptr);
long output_record_send_recv(struct record_send_recv *ptr);
long output_record_audit_log_exit(struct record_audit_log_exit *ptr);
long output_record_as_dynptr(struct bpf_dynptr *ptr, record_type_t record_type);