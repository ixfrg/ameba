#pragma once

/*

    A module to help parse user_input from user arguments.

*/

#include "user/types.h"

/*
    Default output values
*/
static enum output_type default_output_type = OUTPUT_FILE;
static char *default_output_file_path = "/tmp/current_prov_log.json";

/*
    A properly formed argp struct.
*/
extern struct argp global_user_input_argp;

/*
    Parsed user input.
    Assumes successful call to 'user_args_user_must_parse_user_input'.
*/
extern struct user_input global_user_input;

/*
    Parse user arguments (i.e. int main(int argc, char **argv)), and populate dst.

    Return:
        0    => Success
        +ive => Failure
        -ive => Failure
*/
int user_args_user_must_parse_user_input(int argc, char **argv);