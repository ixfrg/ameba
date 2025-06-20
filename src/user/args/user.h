#pragma once

/*

    A module to help parse user_input from user arguments.

*/

#include "user/types.h"

/*
    Parse user arguments (i.e. int main(int argc, char **argv)), and populate dst.

    Return:
        0    => Success
        +ive => Failure
        -ive => Failure
*/
int user_args_user_must_parse_user_input(struct user_input *dst, int argc, char **argv);