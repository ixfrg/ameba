#pragma once

#include <sys/types.h>

#include "user/jsonify/core.h"
#include "common/types.h"


int jsonify_types_write_fd(struct json_buffer *s, const char *key, int val);
int jsonify_types_write_return(struct json_buffer *s, const char *key, int val);
int jsonify_types_write_pid(struct json_buffer *s, const char *key, pid_t val);
int jsonify_types_write_uid(struct json_buffer *s, const char *key, uid_t val);
int jsonify_types_write_gid(struct json_buffer *s, const char *key, gid_t val);
int jsonify_types_write_inode(struct json_buffer *s, const char *key, inode_num_t val);
int jsonify_types_write_event_id(struct json_buffer *s, event_id_t val);
int jsonify_types_write_sys_id(struct json_buffer *s, sys_id_t sys_id);
int jsonify_types_write_elem_sockaddr(struct json_buffer *s, const char *key, struct elem_sockaddr *e_sa);
int jsonify_types_write_common(
    struct json_buffer *s, struct elem_common *e_common, 
    struct elem_timestamp *e_ts, char *record_type_name
);