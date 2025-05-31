#pragma once

#define USERSPACE_CODE
#include "common/control.h"

int user_args_control_must_parse_control_input(struct control_input *dst, int argc, char **argv);