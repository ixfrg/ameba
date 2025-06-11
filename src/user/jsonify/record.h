#pragma once

/*

    A module to help write record types to json_buffer.

    See 'core.h'.

*/

#include "user/jsonify/types.h"

/*
    Write record to json_buffer.
    
    e_common contains the record type. It is cast to record_* based on it's type to get the actual record.

    Set 'write_interpreted' to non-zero value to interpret the record's contents like socket address.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_record(struct json_buffer *s, struct elem_common *e_common, int data_len, int write_interpreted);