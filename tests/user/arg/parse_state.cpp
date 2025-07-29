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
extern "C" {
#include "user/arg/parse_state.h"
}

#include "CppUTest/TestHarness.h"
#include <string.h>

TEST_GROUP(ParseState)
{
    struct arg_parse_state state;

    void setup() {
        // each function resets it or sets it so these values should be overwritten
        memset(&state, 123, sizeof(state));
    }

    void teardown() {}
};

TEST(ParseState, InitSetsExitAndCodeToZero)
{
    arg_parse_state_init(&state);
    CHECK_EQUAL(0, state.exit);
    CHECK_EQUAL(0, state.code);
    CHECK_EQUAL(0, arg_parse_state_is_exit_set(&state));
    CHECK_EQUAL(0, arg_parse_state_get_code(&state));
}

TEST(ParseState, SetExitErrorSetsExitAndCode)
{
    arg_parse_state_set_exit_error(&state, -42);
    CHECK_EQUAL(1, state.exit);
    CHECK_EQUAL(-42, state.code);
    CHECK_EQUAL(1, arg_parse_state_is_exit_set(&state));
    CHECK_EQUAL(-42, arg_parse_state_get_code(&state));
}

TEST(ParseState, SetExitNoErrorSetsExitTrueCodeZero)
{
    arg_parse_state_set_exit_no_error(&state);
    CHECK_EQUAL(1, state.exit);
    CHECK_EQUAL(0, state.code);
    CHECK_EQUAL(1, arg_parse_state_is_exit_set(&state));
    CHECK_EQUAL(0, arg_parse_state_get_code(&state));
}

TEST(ParseState, SetNoExitResetsState)
{
    state.exit = 1;
    state.code = -999;
    arg_parse_state_set_no_exit(&state);
    CHECK_EQUAL(0, state.exit);
    CHECK_EQUAL(0, state.code);
    CHECK_EQUAL(0, arg_parse_state_is_exit_set(&state));
    CHECK_EQUAL(0, arg_parse_state_get_code(&state));
}

TEST(ParseState, NullSafety)
{
    arg_parse_state_init(nullptr);
    arg_parse_state_set_exit_error(nullptr, -1);
    arg_parse_state_set_exit_no_error(nullptr);
    arg_parse_state_set_no_exit(nullptr);
    LONGS_EQUAL(0, arg_parse_state_is_exit_set(nullptr));
    LONGS_EQUAL(0, arg_parse_state_get_code(nullptr));
}

int main(int argc, char** argv)
{
    const char* verboseArgv[] = { argv[0], "-v" };
    return CommandLineTestRunner::RunAllTests(2, verboseArgv);
}