#pragma once

/*

    A module to help write control_input to json_buffer.

    See 'core.h'.

*/

#include "user/jsonify/core.h"
#include "common/control.h"


/*
    Write control_input to json_buffer.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_control_write_control_input(struct json_buffer *s, struct control_input *val);