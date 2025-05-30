#pragma once


#include "bpf/helpers/event_context.bpf.h"


event_id_t ameba_increment_event_id(void);
int ameba_is_event_auditable(struct event_context *e_ctx);
long ameba_write_record_cred_to_output_buffer(struct record_cred *ptr);
long ameba_write_record_namespace_to_output_buffer(struct record_namespace *ptr);
long ameba_write_record_new_process_to_output_buffer(struct record_new_process *ptr);
long ameba_write_record_accept_to_output_buffer(struct record_accept *ptr);
long ameba_write_record_send_recv_to_output_buffer(struct record_send_recv *ptr);
long ameba_write_record_to_output_buffer(struct bpf_dynptr *ptr, record_type_t record_type);

