#pragma once

/*

    A module to help write user_input to json_buffer.

    See 'core.h'.

*/

#include "user/jsonify/core.h"
#include "user/args/user.h"


/*
    Write user_input to json_buffer.

    Return:
        See 'jsonify_core_snprintf'.
*/
int jsonify_user_write_user_input(struct json_buffer *s, struct user_input *val);