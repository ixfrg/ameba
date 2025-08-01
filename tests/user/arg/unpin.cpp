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
#include "user/arg/unpin.h"
#include "user/arg/parse_state.h"
}

#include "user/arg/test_helper.hpp"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <string.h>
#include <stdlib.h>

TEST_GROUP(UnpinArgParse)
{
    struct arg_unpin_with_parse_state parsed;
    struct arg_unpin initial;

    void setup()
    {
        memset(&parsed, 0, sizeof(parsed));
        memset(&initial, 0, sizeof(initial));
    }

    void teardown() {}
};

// ---------- FLAGS ----------

TEST(UnpinArgParse, ParsesHelpSetsNoErrorExit)
{
    char *argv[] = {
        (char *)"unpin",
        (char *)"--help"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_unpin_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_zero_code(&parsed.parse_state);
    test_helper_arg_common_must_be_show_help(&parsed.common);
}

TEST(UnpinArgParse, ParsesVersionSetsNoErrorExit)
{
    char *argv[] = {
        (char *)"unpin",
        (char *)"--version"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_unpin_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_zero_code(&parsed.parse_state);
    test_helper_arg_common_must_be_show_version(&parsed.common);
}

TEST(UnpinArgParse, ParsesUsageSetsNoErrorExit)
{
    char *argv[] = {
        (char *)"unpin",
        (char *)"--usage"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_unpin_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_zero_code(&parsed.parse_state);
    test_helper_arg_common_must_be_show_usage(&parsed.common);
}

// ---------- INVALID ----------

TEST(UnpinArgParse, RejectsUnknownArgument)
{
    char *argv[] = {
        (char *)"unpin",
        (char *)"--foobar"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_unpin_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_negative_code(&parsed.parse_state);
}

// ---------- EMPTY ----------

TEST(UnpinArgParse, ParsesEmptyArgsDoesNotExit)
{
    char *argv[] = {
        (char *)"unpin"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_unpin_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_not_exit(&parsed.parse_state);
    test_helper_arg_common_must_be_all_zero(&parsed.common);
}

int main(int argc, char **argv)
{
    const char *verboseArgv[] = { argv[0], "-v" };
    return CommandLineTestRunner::RunAllTests(2, verboseArgv);
}