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
    #include "user/args/user.h"
}


TEST_GROUP(UserArgUserInputGroup)
{
};

TEST(UserArgUserInputGroup, TestParse)
{
    int argc = 0;
    char* argv[] = {};
    int res = user_args_user_must_parse_user_input(argc, argv);
    CHECK_EQUAL(res, 0);
}

TEST(UserArgUserInputGroup, TestDefaults)
{
    int argc = 0;
    char* argv[] = {};
    int res = user_args_user_must_parse_user_input(argc, argv);
    CHECK_EQUAL(res, 0);
    
    CHECK_EQUAL(global_user_input.c_in.lock, FREE);
    CHECK_EQUAL(global_user_input.c_in.global_mode, IGNORE);
    CHECK_EQUAL(global_user_input.c_in.uid_mode, IGNORE);
    CHECK_EQUAL(global_user_input.c_in.uids_len, 0);
    CHECK_EQUAL(global_user_input.c_in.pid_mode, IGNORE);
    CHECK_EQUAL(global_user_input.c_in.pids_len, 0);
    CHECK_EQUAL(global_user_input.c_in.ppid_mode, IGNORE);
    CHECK_EQUAL(global_user_input.c_in.ppids_len, 0);
    CHECK_EQUAL(global_user_input.c_in.netio_mode, IGNORE);

    CHECK_EQUAL(global_user_input.show_version, 0);

    CHECK_EQUAL(global_user_input.o_type, OUTPUT_FILE);
    STRNCMP_EQUAL(
        global_user_input.output_file.path,
        "/tmp/current_prov_log.json",
        strlen("/tmp/current_prov_log.json")
    );
    CHECK_EQUAL(global_user_input.output_net.ip_family, 0);
    CHECK_EQUAL(global_user_input.output_net.port, -1);
    CHECK_EQUAL(global_user_input.output_net.ip[0], 0);
}

TEST(UserArgUserInputGroup, TestVersion)
{
    int argc = 2;
    char* argv[] = {(char*)"test", (char*)"--version"};
    int res = user_args_user_must_parse_user_input(argc, argv);
    CHECK_EQUAL(res, 0);
    CHECK_EQUAL(global_user_input.show_version, 1);
}

TEST(UserArgUserInputGroup, TestOutputFile)
{
    char* argv[] = {
        (char*)"test",
        (char*)"--file-path",
        (char*)"/tmp/test.json"
    };
    int argc = sizeof(argv) / sizeof(char*);
    int res = user_args_user_must_parse_user_input(argc, argv);
    CHECK_EQUAL(res, 0);

    CHECK_EQUAL(global_user_input.o_type, OUTPUT_FILE);
    STRNCMP_EQUAL(global_user_input.output_file.path, "/tmp/test.json", strlen("/tmp/test.json"));
}
/*
TEST(UserArgUserInputGroup, TestOutputNetValid)
{
    char* argv[] = {
        (char*)"test",
        (char*)"--ip",
        (char*)"0.0.0.0"
    };
    int argc = sizeof(argv) / sizeof(char*);
    int res = user_args_user_must_parse_user_input(argc, argv);
    printf("res=%d\n", res);
    CHECK_EQUAL(res, 0);

    CHECK_EQUAL(global_user_input.o_type, OUTPUT_NET);
    STRNCMP_EQUAL(global_user_input.output_net.ip, "0.0.0.0", strlen("0.0.0.0"));
}
*/
int main(int argc, char** argv)
{
    const char* verboseArgv[] = { argv[0], "-v" };
    return CommandLineTestRunner::RunAllTests(2, verboseArgv);
}