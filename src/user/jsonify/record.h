#pragma once


#include "user/jsonify/types.h"


int jsonify_record_connect(struct json_buffer *s, struct record_connect *data);
int jsonify_record_accept(struct json_buffer *s, struct record_accept *data);
int jsonify_record_namespace(struct json_buffer *s, struct record_namespace *data);
int jsonify_record_new_process(struct json_buffer *s, struct record_new_process *data);
int jsonify_record_cred(struct json_buffer *s, struct record_cred *data);
int jsonify_record_send_recv(struct json_buffer *s, struct record_send_recv *data);
int jsonify_record_bind(struct json_buffer *s, struct record_bind *data);
int jsonify_record_kill(struct json_buffer *s, struct record_kill *data);
int jsonify_record_audit_log_exit(struct json_buffer *s, struct record_audit_log_exit *data);