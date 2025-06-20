#pragma once

/*

    A module to help parse control_input from user arguments.

*/

#include "common/control.h"

/*
    A properly formed argp struct.
*/
extern struct argp global_control_input_argp;

/*
    Parsed control input.
    Assumes successful call to 'user_args_control_must_parse_control_input'.
*/
extern struct control_input global_control_input;

/*
    Parse user arguments (i.e. int main(int argc, char **argv)), and populate dst.

    Return:
        0    => Success
        +ive => Failure
        -ive => Failure
*/
int user_args_control_must_parse_control_input(int argc, char **argv);
