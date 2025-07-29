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
#include "user/arg/common.h"
#include "user/arg/parse_state.h"
}

#include <CppUTest/CommandLineTestRunner.h>
#include "CppUTest/TestHarness.h"

TEST_GROUP(ArgCommonTestGroup)
{
    struct arg_common common;
    struct arg_parse_state state;

    void setup()
    {
        arg_common_init(&common);
        arg_parse_state_init(&state);
    }

    void teardown() {}
};

TEST(ArgCommonTestGroup, InitSetsAllFieldsToZero)
{
    CHECK_EQUAL(0, common.show_help);
    CHECK_EQUAL(0, common.show_usage);
    CHECK_EQUAL(0, common.show_version);
}

TEST(ArgCommonTestGroup, ShowHelpSetsFlagAndExitsZero)
{
    arg_common_show_help(&common, &state);
    CHECK_EQUAL(1, common.show_help);
    CHECK_EQUAL(1, state.exit);
    CHECK_EQUAL(0, state.code);
}

TEST(ArgCommonTestGroup, ShowUsageSetsFlagAndExitsZero)
{
    arg_common_show_usage(&common, &state);
    CHECK_EQUAL(1, common.show_usage);
    CHECK_EQUAL(1, state.exit);
    CHECK_EQUAL(0, state.code);
}

TEST(ArgCommonTestGroup, ShowVersionSetsFlagAndExitsZero)
{
    arg_common_show_version(&common, &state);
    CHECK_EQUAL(1, common.show_version);
    CHECK_EQUAL(1, state.exit);
    CHECK_EQUAL(0, state.code);
}

TEST(ArgCommonTestGroup, UsageHelpVersionSetDetection)
{
    CHECK_EQUAL(0, arg_common_is_usage_help_or_version_set(&common));
    common.show_help = 1;
    CHECK_EQUAL(1, arg_common_is_usage_help_or_version_set(&common));
    common.show_help = 0;
    common.show_usage = 1;
    CHECK_EQUAL(1, arg_common_is_usage_help_or_version_set(&common));
    common.show_usage = 0;
    common.show_version = 1;
    CHECK_EQUAL(1, arg_common_is_usage_help_or_version_set(&common));
}

TEST(ArgCommonTestGroup, NullInputDoesNotCrash)
{
    arg_common_init(NULL);
    arg_common_show_help(NULL, NULL);
    arg_common_show_usage(NULL, NULL);
    arg_common_show_version(NULL, NULL);
    LONGS_EQUAL(0, arg_common_is_usage_help_or_version_set(NULL));
}

int main(int argc, char** argv)
{
    const char* verboseArgv[] = { argv[0], "-v" };
    return CommandLineTestRunner::RunAllTests(2, verboseArgv);
}