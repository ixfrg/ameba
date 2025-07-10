// SPDX-License-Identifier: GPL-3.0-or-later
/*
AMEBA - A Minimal eBPF-based Audit: an eBPF-based Linux telemetry collection tool.
Copyright (C) 2025  Hassaan Irshad

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

extern "C" {
    #include "user/args/helper.h"
}

TEST_GROUP(UserArgHelperGroup)
{
};

TEST(UserArgHelperGroup, TestInit)
{
    struct arg_parse_state a;
    a.exit = 100;
    a.code = 101;

    user_args_helper_state_init(&a);

    CHECK_EQUAL(0, user_args_helper_state_is_exit_set(&a));
    CHECK_EQUAL(0, user_args_helper_state_get_code(&a));
}

TEST(UserArgHelperGroup, TestInitNoSegFault)
{
    user_args_helper_state_init(NULL);
}

TEST(UserArgHelperGroup, TestExitError)
{
    struct arg_parse_state a;

    user_args_helper_state_init(&a);
    user_args_helper_state_set_exit_error(&a, -10);

    CHECK_EQUAL(1, user_args_helper_state_is_exit_set(&a));
    CHECK_EQUAL(-10, user_args_helper_state_get_code(&a));
}

TEST(UserArgHelperGroup, TestExitErrorNoSegFault)
{
    user_args_helper_state_set_exit_error(NULL, -11);
}

TEST(UserArgHelperGroup, TestExitNoError)
{
    struct arg_parse_state a;

    user_args_helper_state_init(&a);
    user_args_helper_state_set_exit_no_error(&a);

    CHECK_EQUAL(1, user_args_helper_state_is_exit_set(&a));
    CHECK_EQUAL(0, user_args_helper_state_get_code(&a));
}

TEST(UserArgHelperGroup, TestExitNoErrorNoSegFault)
{
    user_args_helper_state_set_exit_no_error(NULL);
}

TEST(UserArgHelperGroup, TestNoExit)
{
    struct arg_parse_state a;

    user_args_helper_state_init(&a);

    a.exit = 100;
    a.code = 101;

    user_args_helper_state_set_no_exit(&a);

    CHECK_EQUAL(0, user_args_helper_state_is_exit_set(&a));
    CHECK_EQUAL(0, user_args_helper_state_get_code(&a));
}

TEST(UserArgHelperGroup, TestNoExitNoSegFault)
{
    user_args_helper_state_set_no_exit(NULL);
}

TEST(UserArgHelperGroup, TestExitGetNoSegFault)
{
    user_args_helper_state_is_exit_set(NULL);
}

TEST(UserArgHelperGroup, TestCodeGetNoSegFault)
{
    user_args_helper_state_get_code(NULL);
}

int main(int argc, char** argv)
{
    const char* verboseArgv[] = { argv[0], "-v" };
    return CommandLineTestRunner::RunAllTests(2, verboseArgv);
}