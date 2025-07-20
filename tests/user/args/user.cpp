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

static void check_parse_state_exit_error(struct user_input_arg *i)
{
    if (!i)
        return;
    CHECK_EQUAL(1, i->parse_state.exit);
    CHECK(0 != i->parse_state.code);
}

static void check_parse_state_exit_no_error(struct user_input_arg *i)
{
    if (!i)
        return;
    CHECK_EQUAL(1, i->parse_state.exit);
    CHECK_EQUAL(0, i->parse_state.code);
}

static void check_parse_state_no_exit(struct user_input_arg *i)
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
    struct user_input_arg u_in_arg;
    char* argv[] = {(char*)"test"};
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_no_exit(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestDefaults)
{
    struct user_input_arg u_in_arg;

    char* argv[] = {(char*)"test"};
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_no_exit(&u_in_arg);

    CHECK_EQUAL(IGNORE, u_in_arg.user_input.c_in.global_mode);
    CHECK_EQUAL(IGNORE, u_in_arg.user_input.c_in.uid_mode);
    CHECK_EQUAL(0, u_in_arg.user_input.c_in.uids_len);
    CHECK_EQUAL(IGNORE, u_in_arg.user_input.c_in.pid_mode);
    CHECK_EQUAL(0, u_in_arg.user_input.c_in.pids_len);
    CHECK_EQUAL(IGNORE, u_in_arg.user_input.c_in.ppid_mode);
    CHECK_EQUAL(0, u_in_arg.user_input.c_in.ppids_len);
    CHECK_EQUAL(IGNORE, u_in_arg.user_input.c_in.netio_mode);

    CHECK_EQUAL(OUTPUT_FILE, u_in_arg.user_input.o_type);
    STRNCMP_EQUAL(
        "/tmp/current_prov_log.json",
        u_in_arg.user_input.output_file.path,
        strlen("/tmp/current_prov_log.json")
    );
    CHECK_EQUAL(0, u_in_arg.user_input.output_net.ip_family);
    CHECK_EQUAL(-1, u_in_arg.user_input.output_net.port);
    CHECK_EQUAL(0, u_in_arg.user_input.output_net.ip[0]);
}

TEST(UserArgUserInputGroup, TestNonDefaults)
{
    struct user_input_arg u_in_arg;

    char* argv[] = {
        (char*)"test",
        (char*)"--output-uri",
        (char*)"udp://0.0.0.0:1212",
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
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_no_exit(&u_in_arg);

    CHECK_EQUAL(OUTPUT_NET, u_in_arg.user_input.o_type);
    CHECK_EQUAL(AF_INET, u_in_arg.user_input.output_net.ip_family);
    STRNCMP_EQUAL("0.0.0.0", u_in_arg.user_input.output_net.ip, strlen("0.0.0.0"));
    CHECK_EQUAL(1212, u_in_arg.user_input.output_net.port);

    CHECK_EQUAL(CAPTURE, u_in_arg.user_input.c_in.global_mode);

    CHECK_EQUAL(CAPTURE, u_in_arg.user_input.c_in.uid_mode);
    CHECK_EQUAL(1, u_in_arg.user_input.c_in.uids_len);
    CHECK_EQUAL(1000, u_in_arg.user_input.c_in.uids[0]);

    CHECK_EQUAL(CAPTURE, u_in_arg.user_input.c_in.pid_mode);
    CHECK_EQUAL(1, u_in_arg.user_input.c_in.pids_len);
    CHECK_EQUAL(2000, u_in_arg.user_input.c_in.pids[0]);

    CHECK_EQUAL(CAPTURE, u_in_arg.user_input.c_in.ppid_mode);
    CHECK_EQUAL(1, u_in_arg.user_input.c_in.ppids_len);
    CHECK_EQUAL(3000, u_in_arg.user_input.c_in.ppids[0]);

    CHECK_EQUAL(CAPTURE, u_in_arg.user_input.c_in.netio_mode);

}

TEST(UserArgUserInputGroup, TestVersion)
{
    struct user_input_arg u_in_arg;

    char* argv[] = {(char*)"test", (char*)"--version"};
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_no_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestHelp)
{
    struct user_input_arg u_in_arg;

    char* argv[] = {(char*)"test", (char*)"--help"};
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_no_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestUsage)
{
    struct user_input_arg u_in_arg;

    char* argv[] = {(char*)"test", (char*)"--usage"};
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_no_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestOutputURIMissing)
{
    struct user_input_arg u_in_arg;
    char* argv[] = {
        (char*)"test",
        (char*)"--output-uri"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestOutputNetInvalidArg1)
{
    struct user_input_arg u_in_arg;
    char* argv[] = {
        (char*)"test",
        (char*)"--output-uri",
        (char*)"udp://:1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestOutputNetInvalidArg2)
{
    struct user_input_arg u_in_arg;
    char* argv[] = {
        (char*)"test",
        (char*)"--output-uri",
        (char*)"udp://0.0.0.0"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestOutputFileAbsolute)
{
    struct user_input_arg u_in_arg;

    char* argv[] = {
        (char*)"test",
        (char*)"--output-uri",
        (char*)"file:///tmp/test.json"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_no_exit(&u_in_arg);

    CHECK_EQUAL(OUTPUT_FILE, u_in_arg.user_input.o_type);
    STRNCMP_EQUAL(
        "/tmp/test.json",
        u_in_arg.user_input.output_file.path,
        strlen("/tmp/test.json")
    );
}

TEST(UserArgUserInputGroup, TestOutputFileRelativeInvalid)
{
    struct user_input_arg u_in_arg;

    char* argv[] = {
        (char*)"test",
        (char*)"--output-uri",
        (char*)"file://tmp/test.json"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestOutputNetValidIp4)
{
    struct user_input_arg u_in_arg;

    char* argv[] = {
        (char*)"test",
        (char*)"--output-uri",
        (char*)"udp://0.0.0.0:1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_no_exit(&u_in_arg);

    CHECK_EQUAL(OUTPUT_NET, u_in_arg.user_input.o_type);
    CHECK_EQUAL(AF_INET, u_in_arg.user_input.output_net.ip_family);
    STRNCMP_EQUAL("0.0.0.0", u_in_arg.user_input.output_net.ip, strlen("0.0.0.0"));
    CHECK_EQUAL(1212, u_in_arg.user_input.output_net.port);
}

TEST(UserArgUserInputGroup, TestOutputNetValidIp6)
{
    struct user_input_arg u_in_arg;

    char* argv[] = {
        (char*)"test",
        (char*)"--output-uri",
        (char*)"udp://[::1]:1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_no_exit(&u_in_arg);

    CHECK_EQUAL(OUTPUT_NET, u_in_arg.user_input.o_type);
    CHECK_EQUAL(AF_INET6, u_in_arg.user_input.output_net.ip_family);
    STRNCMP_EQUAL("::1", u_in_arg.user_input.output_net.ip, strlen("::1"));
    CHECK_EQUAL(1212, u_in_arg.user_input.output_net.port);
}

TEST(UserArgUserInputGroup, TestOutputNetInvalidIp4)
{
    struct user_input_arg u_in_arg;
    char* argv[] = {
        (char*)"test",
        (char*)"--output-uri",
        (char*)"udp://0.0.0.0.0:1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestOutputNetInvalidIp6)
{
    struct user_input_arg u_in_arg;
    char* argv[] = {
        (char*)"test",
        (char*)"--output-uri",
        (char*)"udp://[::::::1]:1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestNonDefaultsShort)
{
    struct user_input_arg u_in_arg;

    char* argv[] = {
        (char*)"test",
        (char*)"-o",
        (char*)"udp://0.0.0.0:1212",
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
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_no_exit(&u_in_arg);

    CHECK_EQUAL(OUTPUT_NET, u_in_arg.user_input.o_type);
    CHECK_EQUAL(AF_INET, u_in_arg.user_input.output_net.ip_family);
    STRNCMP_EQUAL("0.0.0.0", u_in_arg.user_input.output_net.ip, strlen("0.0.0.0"));
    CHECK_EQUAL(1212, u_in_arg.user_input.output_net.port);

    CHECK_EQUAL(CAPTURE, u_in_arg.user_input.c_in.global_mode);
    CHECK_EQUAL(CAPTURE, u_in_arg.user_input.c_in.uid_mode);
    CHECK_EQUAL(1, u_in_arg.user_input.c_in.uids_len);
    CHECK_EQUAL(1000, u_in_arg.user_input.c_in.uids[0]);
    CHECK_EQUAL(CAPTURE, u_in_arg.user_input.c_in.pid_mode);
    CHECK_EQUAL(1, u_in_arg.user_input.c_in.pids_len);
    CHECK_EQUAL(2000, u_in_arg.user_input.c_in.pids[0]);
    CHECK_EQUAL(CAPTURE, u_in_arg.user_input.c_in.ppid_mode);
    CHECK_EQUAL(1, u_in_arg.user_input.c_in.ppids_len);
    CHECK_EQUAL(3000, u_in_arg.user_input.c_in.ppids[0]);
    CHECK_EQUAL(CAPTURE, u_in_arg.user_input.c_in.netio_mode);
}

TEST(UserArgUserInputGroup, TestVersionShort)
{
    struct user_input_arg u_in_arg;

    char* argv[] = {(char*)"test", (char*)"-v"};
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_no_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestHelpShort)
{
    struct user_input_arg u_in_arg;

    char* argv[] = {(char*)"test", (char*)"-?"};
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_no_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestUsageShort)
{
    struct user_input_arg u_in_arg;

    char* argv[] = {(char*)"test", (char*)"-u"};
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_no_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestOutputFileInvalidShort)
{
    struct user_input_arg u_in_arg;
    char* argv[] = {
        (char*)"test",
        (char*)"-o"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestOutputNetInvalidArg1Short)
{
    struct user_input_arg u_in_arg;
    char* argv[] = {
        (char*)"test",
        (char*)"-o",
        (char*)"udp://:1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestOutputNetInvalidArg2Short)
{
    struct user_input_arg u_in_arg;
    char* argv[] = {
        (char*)"test",
        (char*)"-o",
        (char*)"udp://0.0.0.0"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestOutputFileShort)
{
    struct user_input_arg u_in_arg;

    char* argv[] = {
        (char*)"test",
        (char*)"-o",
        (char*)"file:///tmp/test.json"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_no_exit(&u_in_arg);

    CHECK_EQUAL(OUTPUT_FILE, u_in_arg.user_input.o_type);
    STRNCMP_EQUAL("/tmp/test.json", u_in_arg.user_input.output_file.path, strlen("/tmp/test.json"));
}

TEST(UserArgUserInputGroup, TestOutputNetValidIp4Short)
{
    struct user_input_arg u_in_arg;

    char* argv[] = {
        (char*)"test",
        (char*)"-o",
        (char*)"udp://0.0.0.0:1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_no_exit(&u_in_arg);

    CHECK_EQUAL(OUTPUT_NET, u_in_arg.user_input.o_type);
    CHECK_EQUAL(AF_INET, u_in_arg.user_input.output_net.ip_family);
    STRNCMP_EQUAL("0.0.0.0", u_in_arg.user_input.output_net.ip, strlen("0.0.0.0"));
    CHECK_EQUAL(1212, u_in_arg.user_input.output_net.port);
}

TEST(UserArgUserInputGroup, TestOutputNetValidIp6Short)
{
    struct user_input_arg u_in_arg;

    char* argv[] = {
        (char*)"test",
        (char*)"-o",
        (char*)"udp://[::1]:1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_no_exit(&u_in_arg);

    CHECK_EQUAL(OUTPUT_NET, u_in_arg.user_input.o_type);
    CHECK_EQUAL(AF_INET6, u_in_arg.user_input.output_net.ip_family);
    STRNCMP_EQUAL("::1", u_in_arg.user_input.output_net.ip, strlen("::1"));
    CHECK_EQUAL(1212, u_in_arg.user_input.output_net.port);
}

TEST(UserArgUserInputGroup, TestOutputNetNoIpShort)
{
    struct user_input_arg u_in_arg;
    char* argv[] = {
        (char*)"test",
        (char*)"-o",
        (char*)"udp://:1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestOutputNetNoPortShort)
{
    struct user_input_arg u_in_arg;
    char* argv[] = {
        (char*)"test",
        (char*)"-o",
        (char*)"udp://0.0.0.0"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestOutputNetInvalidIp4Short)
{
    struct user_input_arg u_in_arg;
    char* argv[] = {
        (char*)"test",
        (char*)"-o",
        (char*)"udp://0.0.0.0.0:1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_error(&u_in_arg);
}

TEST(UserArgUserInputGroup, TestOutputNetInvalidIp6Short)
{
    struct user_input_arg u_in_arg;
    char* argv[] = {
        (char*)"test",
        (char*)"-o",
        (char*)"udp://[::::::1]:1212"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_user_parse(&u_in_arg, argc, argv);
    check_parse_state_exit_error(&u_in_arg);
}

int main(int argc, char** argv)
{
    const char* verboseArgv[] = { argv[0], "-v" };
    return CommandLineTestRunner::RunAllTests(2, verboseArgv);
}