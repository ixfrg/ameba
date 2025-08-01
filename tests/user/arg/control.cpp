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

extern "C" {
#include "user/arg/control.h"
#include "user/arg/parse_state.h"
}

#include "user/arg/test_helper.hpp"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <string.h>
#include <stdlib.h>

TEST_GROUP(ControlArgParse)
{
    struct arg_control_with_parse_state parsed;
    struct arg_control initial;

    void setup()
    {
        memset(&parsed, 0, sizeof(parsed));
        memset(&initial, 0, sizeof(initial));
    }

    void teardown() {}
};

// ---------- VALID CASES ----------

TEST(ControlArgParse, ParsesValidModeAndLists)
{
    char *argv[] = {
        (char *)"control",
        (char *)"--global-mode", (char *)"capture",
        (char *)"--uid-mode", (char *)"ignore",
        (char *)"--uid-list", (char *)"1000,2000",
        (char *)"--clear-pid-list",
        (char *)"--netio-mode", (char *)"ignore"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_control_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_not_exit(&parsed.parse_state);
    test_helper_arg_common_must_be_all_zero(&parsed.common);

    CHECK_EQUAL(CAPTURE, parsed.arg.control.global_mode);
    CHECK_EQUAL(IGNORE, parsed.arg.control.uid_mode);
    CHECK_EQUAL(2, parsed.arg.control.uids_len);
    CHECK_EQUAL(1000, parsed.arg.control.uids[0]);
    CHECK_EQUAL(2000, parsed.arg.control.uids[1]);
    CHECK_EQUAL(0, parsed.arg.control.pids_len);
    CHECK_EQUAL(IGNORE, parsed.arg.control.netio_mode);
}

// ---------- FLAGS ----------

TEST(ControlArgParse, ParsesUnsafeFlag)
{
    char *argv[] = {
        (char *)"control",
        (char *)"--unsafe"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_control_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_not_exit(&parsed.parse_state);
    CHECK_EQUAL(1, parsed.arg.unsafe);
}

TEST(ControlArgParse, ParsesHelpSetsNoErrorExit)
{
    char *argv[] = {
        (char *)"control",
        (char *)"--help"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_control_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_zero_code(&parsed.parse_state);
    test_helper_arg_common_must_be_show_help(&parsed.common);
}

TEST(ControlArgParse, ParsesVersionSetsNoErrorExit)
{
    char *argv[] = {
        (char *)"control",
        (char *)"--version"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_control_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_zero_code(&parsed.parse_state);
    test_helper_arg_common_must_be_show_version(&parsed.common);
}

TEST(ControlArgParse, ParsesUsageSetsNoErrorExit)
{
    char *argv[] = {
        (char *)"control",
        (char *)"--usage"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_control_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_zero_code(&parsed.parse_state);
    test_helper_arg_common_must_be_show_usage(&parsed.common);
}

// ---------- INVALID CASES ----------

TEST(ControlArgParse, RejectsInvalidMode)
{
    char *argv[] = {
        (char *)"control",
        (char *)"--global-mode", (char *)"observe"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_control_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_negative_code(&parsed.parse_state);
}

TEST(ControlArgParse, RejectsMalformedUidList)
{
    char *argv[] = {
        (char *)"control",
        (char *)"--uid-list", (char *)"abc,123"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_control_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_negative_code(&parsed.parse_state);
}

TEST(ControlArgParse, RejectsTooManyPids)
{
    char list[1024];
    strcpy(list, "1");
    for (int i = 2; i <= 110; ++i)
    {
        strcat(list, ",");
        char num[10];
        snprintf(num, sizeof(num), "%d", i);
        strcat(list, num);
    }

    char *argv[] = {
        (char *)"control",
        (char *)"--pid-list", list
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_control_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_negative_code(&parsed.parse_state);
}

int main(int argc, char **argv)
{
    const char *verboseArgv[] = { argv[0], "-v" };
    return CommandLineTestRunner::RunAllTests(2, verboseArgv);
}