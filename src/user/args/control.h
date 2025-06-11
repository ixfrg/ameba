#pragma once

/*

    A module to help parse control_input from user arguments.

*/

#include "common/control.h"

/*
    Parse user arguments (i.e. int main(int argc, char **argv)), and populate dst.

    Return:
        0    => Success
        +ive => Failure
        -ive => Failure
*/
int user_args_control_must_parse_control_input(struct control_input *dst, int argc, char **argv);