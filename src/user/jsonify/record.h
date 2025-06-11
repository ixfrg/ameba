#pragma once


#include "user/jsonify/types.h"


int jsonify_record_connect(struct json_buffer *s, struct record_connect *data, int write_interpreted);
int jsonify_record_accept(struct json_buffer *s, struct record_accept *data, int write_interpreted);
int jsonify_record_namespace(struct json_buffer *s, struct record_namespace *data, int write_interpreted);
int jsonify_record_new_process(struct json_buffer *s, struct record_new_process *data, int write_interpreted);
int jsonify_record_cred(struct json_buffer *s, struct record_cred *data, int write_interpreted);
int jsonify_record_send_recv(struct json_buffer *s, struct record_send_recv *data, int write_interpreted);
int jsonify_record_bind(struct json_buffer *s, struct record_bind *data, int write_interpreted);
int jsonify_record_kill(struct json_buffer *s, struct record_kill *data, int write_interpreted);
int jsonify_record_audit_log_exit(struct json_buffer *s, struct record_audit_log_exit *data, int write_interpreted);
int jsonify_record(struct json_buffer *s, struct elem_common *e_common, int data_len, int write_interpreted);