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
#include "user/arg/ameba.h"
#include "user/arg/parse_state.h"
}

#include <CppUTest/CommandLineTestRunner.h>
#include "CppUTest/TestHarness.h"
#include "test_helper.hpp"
#include <string.h>
#include <stdlib.h>


TEST_GROUP(AmebaArgParse)
{
    struct arg_ameba_with_parse_state parsed;
    struct arg_ameba initial;

    void setup()
    {
        memset(&parsed, 0, sizeof(parsed));
        memset(&initial, 0, sizeof(initial));
    }

    void teardown() {}
};

// ---------- VALID CASE ----------

TEST(AmebaArgParse, ParsesValidArgs)
{
    char *argv[] = {
        (char *)"ameba",
        (char *)"--log-dir", (char *)"/var/log/ameba",
        (char *)"--log-size", (char *)"104857600",
        (char *)"--log-count", (char *)"5"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_ameba_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_not_exit(&parsed.parse_state);
    test_helper_arg_common_must_be_all_zero(&parsed.common);

    STRCMP_EQUAL("/var/log/ameba", parsed.arg.log_dir_path);
    CHECK_EQUAL(104857600ULL, parsed.arg.log_file_size_bytes);
    CHECK_EQUAL(5U, parsed.arg.log_file_count);
    CHECK_EQUAL(0, parsed.arg.output_stdout);
}

// ---------- INVALID CASES ----------

TEST(AmebaArgParse, RejectsRelativeLogDir)
{
    char *argv[] = {
        (char *)"ameba",
        (char *)"--log-dir", (char *)"relative/path",
        (char *)"--log-size", (char *)"104857600",
        (char *)"--log-count", (char *)"5"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_ameba_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_negative_code(&parsed.parse_state);
    test_helper_arg_common_must_be_all_zero(&parsed.common);
}

TEST(AmebaArgParse, RejectsEmptyLogDir)
{
    char *argv[] = {
        (char *)"ameba",
        (char *)"--log-dir", (char *)"",
        (char *)"--log-size", (char *)"104857600",
        (char *)"--log-count", (char *)"5"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_ameba_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_negative_code(&parsed.parse_state);
    test_helper_arg_common_must_be_all_zero(&parsed.common);
}

TEST(AmebaArgParse, RejectsMissingLogDir)
{
    char *argv[] = {
        (char *)"ameba",
        (char *)"--log-size", (char *)"104857600",
        (char *)"--log-count", (char *)"5"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_ameba_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_negative_code(&parsed.parse_state);
    test_helper_arg_common_must_be_all_zero(&parsed.common);
}

TEST(AmebaArgParse, RejectsTooSmallLogSize)
{
    char *argv[] = {
        (char *)"ameba",
        (char *)"--log-dir", (char *)"/tmp/logs",
        (char *)"--log-size", (char *)"1024", // < 100MB
        (char *)"--log-count", (char *)"5"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_ameba_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_negative_code(&parsed.parse_state);
    test_helper_arg_common_must_be_all_zero(&parsed.common);
}

TEST(AmebaArgParse, RejectsNonNumericLogSize)
{
    char *argv[] = {
        (char *)"ameba",
        (char *)"--log-dir", (char *)"/tmp/logs",
        (char *)"--log-size", (char *)"onehundred",
        (char *)"--log-count", (char *)"5"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_ameba_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_negative_code(&parsed.parse_state);
    test_helper_arg_common_must_be_all_zero(&parsed.common);
}

TEST(AmebaArgParse, RejectsTooLargeLogCount)
{
    char *argv[] = {
        (char *)"ameba",
        (char *)"--log-dir", (char *)"/tmp/logs",
        (char *)"--log-size", (char *)"104857600",
        (char *)"--log-count", (char *)"1000"  // > 100
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_ameba_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_negative_code(&parsed.parse_state);
    test_helper_arg_common_must_be_all_zero(&parsed.common);
}

// // ---------- FLAGS ----------

TEST(AmebaArgParse, ParsesOutputToStdout)
{
    char *argv[] = {
        (char *)"ameba",
        (char *)"--log-dir", (char *)"/tmp/logs",
        (char *)"--log-size", (char *)"104857600",
        (char *)"--log-count", (char *)"5",
        (char *)"--output-stdout"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_ameba_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_not_exit(&parsed.parse_state);
    test_helper_arg_common_must_be_all_zero(&parsed.common);

    CHECK_EQUAL(1, parsed.arg.output_stdout);
}

TEST(AmebaArgParse, ParsesHelpSetsNoErrorExit)
{
    char *argv[] = {
        (char *)"ameba",
        (char *)"--help"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_ameba_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_zero_code(&parsed.parse_state);
    test_helper_arg_common_must_be_show_help(&parsed.common);
}

TEST(AmebaArgParse, ParsesVersionSetsNoErrorExit)
{
    char *argv[] = {
        (char *)"ameba",
        (char *)"--version"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_ameba_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_zero_code(&parsed.parse_state);
    test_helper_arg_common_must_be_show_version(&parsed.common);
}

TEST(AmebaArgParse, ParsesUsageSetsNoErrorExit)
{
    char *argv[] = {
        (char *)"ameba",
        (char *)"--usage"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    arg_ameba_parse(&parsed, &initial, argc, argv);
    test_helper_parse_state_must_be_exit_with_zero_code(&parsed.parse_state);
    test_helper_arg_common_must_be_show_usage(&parsed.common);
}

int main(int argc, char** argv)
{
    const char* verboseArgv[] = { argv[0], "-v" };
    return CommandLineTestRunner::RunAllTests(2, verboseArgv);
}