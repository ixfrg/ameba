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
    CHECK_EQUAL(0, res);
}

TEST(UserArgUserInputGroup, TestDefaults)
{
    struct user_input *u_in = &global_user_input;

    int argc = 0;
    char* argv[] = {};
    int res = user_args_user_must_parse_user_input(argc, argv);
    CHECK_EQUAL(0, res);
    
    CHECK_EQUAL(FREE, u_in->c_in.lock);
    CHECK_EQUAL(IGNORE, u_in->c_in.global_mode);
    CHECK_EQUAL(IGNORE, u_in->c_in.uid_mode);
    CHECK_EQUAL(0, u_in->c_in.uids_len);
    CHECK_EQUAL(IGNORE, u_in->c_in.pid_mode);
    CHECK_EQUAL(0, u_in->c_in.pids_len);
    CHECK_EQUAL(IGNORE, u_in->c_in.ppid_mode);
    CHECK_EQUAL(0, u_in->c_in.ppids_len);
    CHECK_EQUAL(IGNORE, u_in->c_in.netio_mode);

    CHECK_EQUAL(0, u_in->show_version);

    CHECK_EQUAL(OUTPUT_FILE, u_in->o_type);
    STRNCMP_EQUAL(
        "/tmp/current_prov_log.json",
        u_in->output_file.path,
        strlen("/tmp/current_prov_log.json")
    );
    CHECK_EQUAL(0, u_in->output_net.ip_family);
    CHECK_EQUAL(-1, u_in->output_net.port);
    CHECK_EQUAL(0, u_in->output_net.ip[0]);
}

TEST(UserArgUserInputGroup, TestVersion)
{
    struct user_input *u_in = &global_user_input;

    int argc = 2;
    char* argv[] = {(char*)"test", (char*)"--version"};
    int res = user_args_user_must_parse_user_input(argc, argv);
    CHECK_EQUAL(0, res);
    CHECK_EQUAL(1, u_in->show_version);
}

TEST(UserArgUserInputGroup, TestOutputFile)
{
    struct user_input *u_in = &global_user_input;

    char* argv[] = {
        (char*)"test",
        (char*)"--file-path",
        (char*)"/tmp/test.json"
    };
    int argc = sizeof(argv) / sizeof(char*);
    int res = user_args_user_must_parse_user_input(argc, argv);
    CHECK_EQUAL(0, res);

    CHECK_EQUAL(OUTPUT_FILE, u_in->o_type);
    STRNCMP_EQUAL(
        "/tmp/test.json",
        u_in->output_file.path,
        strlen("/tmp/test.json")
    );
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
    CHECK_EQUAL(0, res);

    CHECK_EQUAL(OUTPUT_NET, u_in->o_type);
    STRNCMP_EQUAL("0.0.0.0", u_in->output_net.ip, strlen("0.0.0.0"));
}
*/
int main(int argc, char** argv)
{
    const char* verboseArgv[] = { argv[0], "-v" };
    return CommandLineTestRunner::RunAllTests(2, verboseArgv);
}