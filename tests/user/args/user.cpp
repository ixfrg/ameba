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
    #include "user/args/helper.h"
}

static void check_parse_state_exit_error(struct user_input *i)
{
    if (!i)
        return;
    CHECK_EQUAL(1, i->parse_state.exit);
    CHECK(0 != i->parse_state.code);
}

static void check_parse_state_exit_no_error(struct user_input *i)
{
    if (!i)
        return;
    CHECK_EQUAL(1, i->parse_state.exit);
    CHECK_EQUAL(0, i->parse_state.code);
}

static void check_parse_state_no_exit(struct user_input *i)
{
    if (!i)
        return;
    CHECK_EQUAL(0, i->parse_state.exit);
}

TEST_GROUP(UserArgUserInputGroup)
{
};

TEST(UserArgUserInputGroup, TestParse)
{
    struct user_input u_in;
    char* argv[] = {(char*)"test"};
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_no_exit(&u_in);
}

TEST(UserArgUserInputGroup, TestDefaults)
{
    struct user_input u_in;

    char* argv[] = {(char*)"test"};
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_no_exit(&u_in);
    
    CHECK_EQUAL(FREE, u_in.c_in.lock);
    CHECK_EQUAL(IGNORE, u_in.c_in.global_mode);
    CHECK_EQUAL(IGNORE, u_in.c_in.uid_mode);
    CHECK_EQUAL(0, u_in.c_in.uids_len);
    CHECK_EQUAL(IGNORE, u_in.c_in.pid_mode);
    CHECK_EQUAL(0, u_in.c_in.pids_len);
    CHECK_EQUAL(IGNORE, u_in.c_in.ppid_mode);
    CHECK_EQUAL(0, u_in.c_in.ppids_len);
    CHECK_EQUAL(IGNORE, u_in.c_in.netio_mode);

    CHECK_EQUAL(OUTPUT_FILE, u_in.o_type);
    STRNCMP_EQUAL(
        "/tmp/current_prov_log.json",
        u_in.output_file.path,
        strlen("/tmp/current_prov_log.json")
    );
    CHECK_EQUAL(0, u_in.output_net.ip_family);
    CHECK_EQUAL(-1, u_in.output_net.port);
    CHECK_EQUAL(0, u_in.output_net.ip[0]);
}

TEST(UserArgUserInputGroup, TestNonDefaults)
{
    struct user_input u_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--ip",
        (char*)"0.0.0.0",
        (char*)"--port",
        (char*)"1212",
        (char*)"--global-mode",
        (char*)"capture",
        (char*)"--uid-mode",
        (char*)"capture",
        (char*)"--uid-list",
        (char*)"1000",
        (char*)"--pid-mode",
        (char*)"capture",
        (char*)"--pid-list",
        (char*)"2000",
        (char*)"--ppid-mode",
        (char*)"capture",
        (char*)"--ppid-list",
        (char*)"3000",
        (char*)"--netio-mode",
        (char*)"capture",
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_no_exit(&u_in);

    CHECK_EQUAL(OUTPUT_NET, u_in.o_type);
    CHECK_EQUAL(AF_INET, u_in.output_net.ip_family);
    STRNCMP_EQUAL("0.0.0.0", u_in.output_net.ip, strlen("0.0.0.0"));
    CHECK_EQUAL(1212, u_in.output_net.port);

    CHECK_EQUAL(CAPTURE, u_in.c_in.global_mode);

    CHECK_EQUAL(CAPTURE, u_in.c_in.uid_mode);
    CHECK_EQUAL(1, u_in.c_in.uids_len);
    CHECK_EQUAL(1000, u_in.c_in.uids[0]);

    CHECK_EQUAL(CAPTURE, u_in.c_in.pid_mode);
    CHECK_EQUAL(1, u_in.c_in.pids_len);
    CHECK_EQUAL(2000, u_in.c_in.pids[0]);

    CHECK_EQUAL(CAPTURE, u_in.c_in.ppid_mode);
    CHECK_EQUAL(1, u_in.c_in.ppids_len);
    CHECK_EQUAL(3000, u_in.c_in.ppids[0]);

    CHECK_EQUAL(CAPTURE, u_in.c_in.netio_mode);

}

TEST(UserArgUserInputGroup, TestVersion)
{
    struct user_input u_in;

    char* argv[] = {(char*)"test", (char*)"--version"};
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_no_error(&u_in);
}

TEST(UserArgUserInputGroup, TestHelp)
{
    struct user_input u_in;

    char* argv[] = {(char*)"test", (char*)"--help"};
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_no_error(&u_in);
}

TEST(UserArgUserInputGroup, TestUsage)
{
    struct user_input u_in;

    char* argv[] = {(char*)"test", (char*)"--usage"};
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_no_error(&u_in);
}

TEST(UserArgUserInputGroup, TestOutputFileInvalid)
{
    struct user_input u_in;
    char* argv[] = {
        (char*)"test",
        (char*)"--file-path"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_error(&u_in);
}

TEST(UserArgUserInputGroup, TestOutputNetInvalidArg1)
{
    struct user_input u_in;
    char* argv[] = {
        (char*)"test",
        (char*)"--ip",
        (char*)"--port",
        (char*)"1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_error(&u_in);
}

TEST(UserArgUserInputGroup, TestOutputNetInvalidArg2)
{
    struct user_input u_in;
    char* argv[] = {
        (char*)"test",
        (char*)"--ip",
        (char*)"0.0.0.0",
        (char*)"--port"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_error(&u_in);
}

TEST(UserArgUserInputGroup, TestOutputFile)
{
    struct user_input u_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--file-path",
        (char*)"/tmp/test.json"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_no_exit(&u_in);

    CHECK_EQUAL(OUTPUT_FILE, u_in.o_type);
    STRNCMP_EQUAL(
        "/tmp/test.json",
        u_in.output_file.path,
        strlen("/tmp/test.json")
    );
}

TEST(UserArgUserInputGroup, TestOutputNetValidIp4)
{
    struct user_input u_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--ip",
        (char*)"0.0.0.0",
        (char*)"--port",
        (char*)"1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_no_exit(&u_in);

    CHECK_EQUAL(OUTPUT_NET, u_in.o_type);
    CHECK_EQUAL(AF_INET, u_in.output_net.ip_family);
    STRNCMP_EQUAL("0.0.0.0", u_in.output_net.ip, strlen("0.0.0.0"));
    CHECK_EQUAL(1212, u_in.output_net.port);
}

TEST(UserArgUserInputGroup, TestOutputNetValidIp6)
{
    struct user_input u_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--ip",
        (char*)"::1",
        (char*)"--port",
        (char*)"1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_no_exit(&u_in);

    CHECK_EQUAL(OUTPUT_NET, u_in.o_type);
    CHECK_EQUAL(AF_INET6, u_in.output_net.ip_family);
    STRNCMP_EQUAL("::1", u_in.output_net.ip, strlen("::1"));
    CHECK_EQUAL(1212, u_in.output_net.port);
}

TEST(UserArgUserInputGroup, TestOutputNetNoIp)
{
    struct user_input u_in;
    char* argv[] = {
        (char*)"test",
        (char*)"--port",
        (char*)"1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_error(&u_in);
}

TEST(UserArgUserInputGroup, TestOutputNetNoPort)
{
    struct user_input u_in;
    char* argv[] = {
        (char*)"test",
        (char*)"--ip",
        (char*)"0.0.0.0"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_error(&u_in);
}

TEST(UserArgUserInputGroup, TestOutputNetInvalidIp4)
{
    struct user_input u_in;
    char* argv[] = {
        (char*)"test",
        (char*)"--ip",
        (char*)"0.0.0.0.0",
        (char*)"--port",
        (char*)"1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_error(&u_in);
}

TEST(UserArgUserInputGroup, TestOutputNetInvalidIp6)
{
    struct user_input u_in;
    char* argv[] = {
        (char*)"test",
        (char*)"--ip",
        (char*)"::::::1",
        (char*)"--port",
        (char*)"1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_error(&u_in);
}

TEST(UserArgUserInputGroup, TestNonDefaultsShort)
{
    struct user_input u_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-N",
        (char*)"0.0.0.0",
        (char*)"-s",
        (char*)"1212",
        (char*)"--global-mode",
        (char*)"capture",
        (char*)"--uid-mode",
        (char*)"capture",
        (char*)"--uid-list",
        (char*)"1000",
        (char*)"--pid-mode",
        (char*)"capture",
        (char*)"--pid-list",
        (char*)"2000",
        (char*)"--ppid-mode",
        (char*)"capture",
        (char*)"--ppid-list",
        (char*)"3000",
        (char*)"--netio-mode",
        (char*)"capture",
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_no_exit(&u_in);

    CHECK_EQUAL(OUTPUT_NET, u_in.o_type);
    CHECK_EQUAL(AF_INET, u_in.output_net.ip_family);
    STRNCMP_EQUAL("0.0.0.0", u_in.output_net.ip, strlen("0.0.0.0"));
    CHECK_EQUAL(1212, u_in.output_net.port);

    CHECK_EQUAL(CAPTURE, u_in.c_in.global_mode);
    CHECK_EQUAL(CAPTURE, u_in.c_in.uid_mode);
    CHECK_EQUAL(1, u_in.c_in.uids_len);
    CHECK_EQUAL(1000, u_in.c_in.uids[0]);
    CHECK_EQUAL(CAPTURE, u_in.c_in.pid_mode);
    CHECK_EQUAL(1, u_in.c_in.pids_len);
    CHECK_EQUAL(2000, u_in.c_in.pids[0]);
    CHECK_EQUAL(CAPTURE, u_in.c_in.ppid_mode);
    CHECK_EQUAL(1, u_in.c_in.ppids_len);
    CHECK_EQUAL(3000, u_in.c_in.ppids[0]);
    CHECK_EQUAL(CAPTURE, u_in.c_in.netio_mode);
}

TEST(UserArgUserInputGroup, TestVersionShort)
{
    struct user_input u_in;

    char* argv[] = {(char*)"test", (char*)"-v"};
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_no_error(&u_in);
}

TEST(UserArgUserInputGroup, TestHelpShort)
{
    struct user_input u_in;

    char* argv[] = {(char*)"test", (char*)"-?"};
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_no_error(&u_in);
}

TEST(UserArgUserInputGroup, TestUsageShort)
{
    struct user_input u_in;

    char* argv[] = {(char*)"test", (char*)"-u"};
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_no_error(&u_in);
}

TEST(UserArgUserInputGroup, TestOutputFileInvalidShort)
{
    struct user_input u_in;
    char* argv[] = {
        (char*)"test",
        (char*)"-f"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_error(&u_in);
}

TEST(UserArgUserInputGroup, TestOutputNetInvalidArg1Short)
{
    struct user_input u_in;
    char* argv[] = {
        (char*)"test",
        (char*)"-N",
        (char*)"-s",
        (char*)"1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_error(&u_in);
}

TEST(UserArgUserInputGroup, TestOutputNetInvalidArg2Short)
{
    struct user_input u_in;
    char* argv[] = {
        (char*)"test",
        (char*)"-N",
        (char*)"0.0.0.0",
        (char*)"-s"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_error(&u_in);
}

TEST(UserArgUserInputGroup, TestOutputFileShort)
{
    struct user_input u_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-f",
        (char*)"/tmp/test.json"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_no_exit(&u_in);

    CHECK_EQUAL(OUTPUT_FILE, u_in.o_type);
    STRNCMP_EQUAL("/tmp/test.json", u_in.output_file.path, strlen("/tmp/test.json"));
}

TEST(UserArgUserInputGroup, TestOutputNetValidIp4Short)
{
    struct user_input u_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-N",
        (char*)"0.0.0.0",
        (char*)"-s",
        (char*)"1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_no_exit(&u_in);

    CHECK_EQUAL(OUTPUT_NET, u_in.o_type);
    CHECK_EQUAL(AF_INET, u_in.output_net.ip_family);
    STRNCMP_EQUAL("0.0.0.0", u_in.output_net.ip, strlen("0.0.0.0"));
    CHECK_EQUAL(1212, u_in.output_net.port);
}

TEST(UserArgUserInputGroup, TestOutputNetValidIp6Short)
{
    struct user_input u_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-N",
        (char*)"::1",
        (char*)"-s",
        (char*)"1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_no_exit(&u_in);

    CHECK_EQUAL(OUTPUT_NET, u_in.o_type);
    CHECK_EQUAL(AF_INET6, u_in.output_net.ip_family);
    STRNCMP_EQUAL("::1", u_in.output_net.ip, strlen("::1"));
    CHECK_EQUAL(1212, u_in.output_net.port);
}

TEST(UserArgUserInputGroup, TestOutputNetNoIpShort)
{
    struct user_input u_in;
    char* argv[] = {
        (char*)"test",
        (char*)"-s",
        (char*)"1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_error(&u_in);
}

TEST(UserArgUserInputGroup, TestOutputNetNoPortShort)
{
    struct user_input u_in;
    char* argv[] = {
        (char*)"test",
        (char*)"-N",
        (char*)"0.0.0.0"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_error(&u_in);
}

TEST(UserArgUserInputGroup, TestOutputNetInvalidIp4Short)
{
    struct user_input u_in;
    char* argv[] = {
        (char*)"test",
        (char*)"-N",
        (char*)"0.0.0.0.0",
        (char*)"-s",
        (char*)"1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_error(&u_in);
}

TEST(UserArgUserInputGroup, TestOutputNetInvalidIp6Short)
{
    struct user_input u_in;
    char* argv[] = {
        (char*)"test",
        (char*)"-N",
        (char*)"::::::1",
        (char*)"-s",
        (char*)"1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in, argc, argv);
    check_parse_state_exit_error(&u_in);
}

int main(int argc, char** argv)
{
    const char* verboseArgv[] = { argv[0], "-v" };
    return CommandLineTestRunner::RunAllTests(2, verboseArgv);
}