#pragma once

/*

    A module to help write high-level types to json_buffer.

    See 'core.h'.

*/

#include <sys/types.h>

#include "common/types.h"

#include "user/jsonify/core.h"


/*
    Write [,]"key":val where val is a file descriptor.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_types_write_fd(struct json_buffer *s, const char *key, int val);

/*
    Write [,]"key":val where val is a return value.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_types_write_return(struct json_buffer *s, const char *key, int val);

/*
    Write [,]"key":val where val is ssize_t.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_types_write_ssize(struct json_buffer *s, const char *key, ssize_t val);

/*
    Write [,]"key":val where val is pid_t.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_types_write_pid(struct json_buffer *s, const char *key, pid_t val);

/*
    Write [,]"key":val where val is uid_t.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_types_write_uid(struct json_buffer *s, const char *key, uid_t val);

/*
    Write [,]"key":val where val is gid_t.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_types_write_gid(struct json_buffer *s, const char *key, gid_t val);

/*
    Write [,]"key":val where val is inode_num_t.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_types_write_inode(struct json_buffer *s, const char *key, inode_num_t val);

/*
    Write [,]"event_id":val where val is event_id_t.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_types_write_event_id(struct json_buffer *s, event_id_t val);

/*
    Write [,]"sys_id":val where val is sys_id_t.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_types_write_sys_id(struct json_buffer *s, sys_id_t sys_id);

/*
    Write [,]"sys_name":"val_sys_name" where val_sys_name is interpreted from sys_id.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_types_write_sys_name(struct json_buffer *s, sys_id_t sys_id);

/*
    Write:
        [,]"las_audit":
        {
            "event_id": e_las_ts->event_id,
            "time": seconds.milliseconds
        }
        , where val is elem_las_timestamp.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_types_write_elem_las_timestamp(struct json_buffer *s, struct elem_las_timestamp *e_las_ts);

/*
    Write:
        [,]"key":e_sa where written format of e_sa is dependent on the data inside e_sa.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_types_write_elem_sockaddr(struct json_buffer *s, const char *key, struct elem_sockaddr *e_sa);

/*
    Write:
        [,]"record_name":"record_type_name"
        ,"record_type":e_common->record_type
        ,"record_version":e_common->version
        ,<jsonify_types_write_elem_timestamp>
        [,"task_ctx_id":e_common->task_ctx_id]
    
    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_types_write_common(
    struct json_buffer *s, struct elem_common *e_common, 
    struct elem_timestamp *e_ts, char *record_type_name
);