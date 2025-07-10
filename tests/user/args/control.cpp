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
    #include "user/args/control.h"
    #include "user/args/helper.h"
}


static void check_parse_state_exit_error(struct control_input *i)
{
    if (!i)
        return;
    CHECK_EQUAL(1, i->parse_state.exit);
    CHECK(0 != i->parse_state.code);
}

__attribute__((unused)) static void check_parse_state_exit_no_error(struct control_input *i)
{
    if (!i)
        return;
    CHECK_EQUAL(1, i->parse_state.exit);
    CHECK_EQUAL(0, i->parse_state.code);
}

static void check_parse_state_no_exit(struct control_input *i)
{
    if (!i)
        return;
    CHECK_EQUAL(0, i->parse_state.exit);
}

TEST_GROUP(UserArgControlGroup)
{
};

TEST(UserArgControlGroup, TestParse)
{
    struct control_input c_in;
    char* argv[] = {
        (char*)"test"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
}

TEST(UserArgControlGroup, TestDefaults)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);

    CHECK_EQUAL(FREE, c_in.lock);
    CHECK_EQUAL(IGNORE, c_in.global_mode);
    CHECK_EQUAL(IGNORE, c_in.uid_mode);
    CHECK_EQUAL(0, c_in.uids_len);
    CHECK_EQUAL(IGNORE, c_in.pid_mode);
    CHECK_EQUAL(0, c_in.pids_len);
    CHECK_EQUAL(IGNORE, c_in.ppid_mode);
    CHECK_EQUAL(0, c_in.ppids_len);
    CHECK_EQUAL(IGNORE, c_in.netio_mode);
}

TEST(UserArgControlGroup, TestGlobalModeCapture)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--global-mode",
        (char*)"capture"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(CAPTURE, c_in.global_mode);
}

TEST(UserArgControlGroup, TestGlobalModeInvalid)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--global-mode",
        (char*)"invalid"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_exit_error(&c_in);
}

TEST(UserArgControlGroup, TestNetioModeCapture)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--netio-mode",
        (char*)"capture"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(CAPTURE, c_in.netio_mode);
}

TEST(UserArgControlGroup, TestUidModeIgnoreNone)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--uid-mode",
        (char*)"ignore"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.uid_mode);
    CHECK_EQUAL(0, c_in.uids_len);
}

TEST(UserArgControlGroup, TestUidModeCaptureNone)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--uid-mode",
        (char*)"capture"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(CAPTURE, c_in.uid_mode);
    CHECK_EQUAL(0, c_in.uids_len);
}

TEST(UserArgControlGroup, TestUidModeCaptureSingle)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--uid-mode",
        (char*)"capture",
        (char*)"--uid-list",
        (char*)"1000"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(CAPTURE, c_in.uid_mode);
    CHECK_EQUAL(1, c_in.uids_len);
    CHECK_EQUAL(1000, c_in.uids[0]);
}

TEST(UserArgControlGroup, TestUidModeIgnoreMultiple)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--uid-mode",
        (char*)"ignore",
        (char*)"--uid-list",
        (char*)"1000,1001"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.uid_mode);
    CHECK_EQUAL(2, c_in.uids_len);
    CHECK_EQUAL(1000, c_in.uids[0]);
    CHECK_EQUAL(1001, c_in.uids[1]);
}

TEST(UserArgControlGroup, TestUidModeIgnoreMax)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--uid-mode",
        (char*)"ignore",
        (char*)"--uid-list",
        (char*)"1000,1001,1002,1003,1004,1005,1006,1007,1008,1009"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.uid_mode);
    CHECK_EQUAL(10 ,c_in.uids_len);
    for (int i = 0; i < 10; ++i) {
        CHECK_EQUAL(1000 + i, c_in.uids[i]);
    }
}

TEST(UserArgControlGroup, TestUidModeIgnoreMaxPlus1)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--uid-mode",
        (char*)"ignore",
        (char*)"--uid-list",
        (char*)"1000,1001,1002,1003,1004,1005,1006,1007,1008,1009,1010"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_exit_error(&c_in);
}

TEST(UserArgControlGroup, TestPidModeIgnoreNone)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--pid-mode",
        (char*)"ignore"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.pid_mode);
    CHECK_EQUAL(0, c_in.pids_len);
}

TEST(UserArgControlGroup, TestPidModeCaptureNone)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--pid-mode",
        (char*)"capture"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(CAPTURE, c_in.pid_mode);
    CHECK_EQUAL(0, c_in.pids_len);
}

TEST(UserArgControlGroup, TestPidModeCaptureSingle)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--pid-mode",
        (char*)"capture",
        (char*)"--pid-list",
        (char*)"1234"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(CAPTURE, c_in.pid_mode);
    CHECK_EQUAL(1, c_in.pids_len);
    CHECK_EQUAL(1234, c_in.pids[0]);
}

TEST(UserArgControlGroup, TestPidModeIgnoreMultiple)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--pid-mode",
        (char*)"ignore",
        (char*)"--pid-list",
        (char*)"1234,5678"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.pid_mode);
    CHECK_EQUAL(2, c_in.pids_len);
    CHECK_EQUAL(1234, c_in.pids[0]);
    CHECK_EQUAL(5678, c_in.pids[1]);
}

TEST(UserArgControlGroup, TestPidModeIgnoreMax)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--pid-mode",
        (char*)"ignore", 
        (char*)"--pid-list",
        (char*)"1000,1001,1002,1003,1004,1005,1006,1007,1008,1009"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.pid_mode);
    CHECK_EQUAL(10, c_in.pids_len);
    for (int i = 0; i < 10; ++i) {
        CHECK_EQUAL(1000 + i, c_in.pids[i]);
    }
}

TEST(UserArgControlGroup, TestPidModeIgnoreMaxPlus1)
{
    struct control_input c_in;
    char* argv[] = {
        (char*)"test",
        (char*)"--pid-mode",
        (char*)"ignore",
        (char*)"--pid-list",
        (char*)"1000,1001,1002,1003,1004,1005,1006,1007,1008,1009,1010"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_exit_error(&c_in);
}

TEST(UserArgControlGroup, TestPpidModeIgnoreNone)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--ppid-mode",
        (char*)"ignore"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.ppid_mode);
    CHECK_EQUAL(0, c_in.ppids_len);
}

TEST(UserArgControlGroup, TestPpidModeCaptureNone)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--ppid-mode",
        (char*)"capture"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(CAPTURE, c_in.ppid_mode);
    CHECK_EQUAL(0, c_in.ppids_len);
}

TEST(UserArgControlGroup, TestPpidModeCaptureSingle)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--ppid-mode",
        (char*)"capture",
        (char*)"--ppid-list",
        (char*)"4321"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(CAPTURE, c_in.ppid_mode);
    CHECK_EQUAL(1, c_in.ppids_len);
    CHECK_EQUAL(4321, c_in.ppids[0]);
}

TEST(UserArgControlGroup, TestPpidModeIgnoreMultiple)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--ppid-mode",
        (char*)"ignore",
        (char*)"--ppid-list",
        (char*)"4321,8765"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.ppid_mode);
    CHECK_EQUAL(2, c_in.ppids_len);
    CHECK_EQUAL(4321, c_in.ppids[0]);
    CHECK_EQUAL(8765, c_in.ppids[1]);
}

TEST(UserArgControlGroup, TestPpidModeIgnoreMax)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--ppid-mode",
        (char*)"ignore", 
        (char*)"--ppid-list",
        (char*)"2000,2001,2002,2003,2004,2005,2006,2007,2008,2009"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.ppid_mode);
    CHECK_EQUAL(10, c_in.ppids_len);
    for (int i = 0; i < 10; ++i) {
        CHECK_EQUAL(2000 + i, c_in.ppids[i]);
    }
}

TEST(UserArgControlGroup, TestPpidModeIgnoreMaxPlus1)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"--ppid-mode",
        (char*)"ignore", 
        (char*)"--ppid-list",
        (char*)"2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_exit_error(&c_in);
}

TEST(UserArgControlGroup, TestGlobalModeCaptureShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-g",
        (char*)"capture"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(CAPTURE, c_in.global_mode);
}

TEST(UserArgControlGroup, TestGlobalModeInvalidShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-g",
        (char*)"invalid"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_exit_error(&c_in);
}

TEST(UserArgControlGroup, TestNetioModeCaptureShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-n",
        (char*)"capture"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(CAPTURE, c_in.netio_mode);
}

TEST(UserArgControlGroup, TestUidModeIgnoreNoneShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-c",
        (char*)"ignore"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.uid_mode);
    CHECK_EQUAL(0, c_in.uids_len);
}

TEST(UserArgControlGroup, TestUidModeCaptureNoneShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-c",
        (char*)"capture"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(CAPTURE, c_in.uid_mode);
    CHECK_EQUAL(0, c_in.uids_len);
}

TEST(UserArgControlGroup, TestUidModeCaptureSingleShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-c",
        (char*)"capture",
        (char*)"-C",
        (char*)"1000"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(CAPTURE, c_in.uid_mode);
    CHECK_EQUAL(1, c_in.uids_len);
    CHECK_EQUAL(1000, c_in.uids[0]);
}

TEST(UserArgControlGroup, TestUidModeIgnoreMultipleShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-c",
        (char*)"ignore",
        (char*)"-C",
        (char*)"1000,1001"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.uid_mode);
    CHECK_EQUAL(2, c_in.uids_len);
    CHECK_EQUAL(1000, c_in.uids[0]);
    CHECK_EQUAL(1001, c_in.uids[1]);
}

TEST(UserArgControlGroup, TestUidModeIgnoreMaxShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-c",
        (char*)"ignore",
        (char*)"-C",
        (char*)"1000,1001,1002,1003,1004,1005,1006,1007,1008,1009"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.uid_mode);
    CHECK_EQUAL(10, c_in.uids_len);
    for (int i = 0; i < 10; ++i) {
        CHECK_EQUAL(1000 + i, c_in.uids[i]);
    }
}

TEST(UserArgControlGroup, TestUidModeIgnoreMaxPlus1Short)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-c",
        (char*)"ignore",
        (char*)"-C",
        (char*)"1000,1001,1002,1003,1004,1005,1006,1007,1008,1009,1010"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_exit_error(&c_in);
}

TEST(UserArgControlGroup, TestPidModeIgnoreNoneShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-p",
        (char*)"ignore"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.pid_mode);
    CHECK_EQUAL(0, c_in.pids_len);
}

TEST(UserArgControlGroup, TestPidModeCaptureNoneShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-p",
        (char*)"capture"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(CAPTURE, c_in.pid_mode);
    CHECK_EQUAL(0, c_in.pids_len);
}

TEST(UserArgControlGroup, TestPidModeCaptureSingleShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-p",
        (char*)"capture",
        (char*)"-P",
        (char*)"1234"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(CAPTURE, c_in.pid_mode);
    CHECK_EQUAL(1, c_in.pids_len);
    CHECK_EQUAL(1234, c_in.pids[0]);
}

TEST(UserArgControlGroup, TestPidModeIgnoreMultipleShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-p",
        (char*)"ignore",
        (char*)"-P",
        (char*)"1234,5678"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.pid_mode);
    CHECK_EQUAL(2, c_in.pids_len);
    CHECK_EQUAL(1234, c_in.pids[0]);
    CHECK_EQUAL(5678, c_in.pids[1]);
}

TEST(UserArgControlGroup, TestPidModeIgnoreMaxShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-p",
        (char*)"ignore",
        (char*)"-P",
        (char*)"1000,1001,1002,1003,1004,1005,1006,1007,1008,1009"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.pid_mode);
    CHECK_EQUAL(10, c_in.pids_len);
    for (int i = 0; i < 10; ++i) {
        CHECK_EQUAL(1000 + i, c_in.pids[i]);
    }
}

TEST(UserArgControlGroup, TestPidModeIgnoreMaxPlus1Short)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-p",
        (char*)"ignore",
        (char*)"-P",
        (char*)"1000,1001,1002,1003,1004,1005,1006,1007,1008,1009,1010"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_exit_error(&c_in);
}

TEST(UserArgControlGroup, TestPpidModeIgnoreNoneShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-k",
        (char*)"ignore"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.ppid_mode);
    CHECK_EQUAL(0, c_in.ppids_len);
}

TEST(UserArgControlGroup, TestPpidModeCaptureNoneShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-k",
        (char*)"capture"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(CAPTURE, c_in.ppid_mode);
    CHECK_EQUAL(0, c_in.ppids_len);
}

TEST(UserArgControlGroup, TestPpidModeCaptureSingleShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-k",
        (char*)"capture",
        (char*)"-K",
        (char*)"4321"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(CAPTURE, c_in.ppid_mode);
    CHECK_EQUAL(1, c_in.ppids_len);
    CHECK_EQUAL(4321, c_in.ppids[0]);
}

TEST(UserArgControlGroup, TestPpidModeIgnoreMultipleShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-k",
        (char*)"ignore",
        (char*)"-K",
        (char*)"4321,8765"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.ppid_mode);
    CHECK_EQUAL(2, c_in.ppids_len);
    CHECK_EQUAL(4321, c_in.ppids[0]);
    CHECK_EQUAL(8765, c_in.ppids[1]);
}

TEST(UserArgControlGroup, TestPpidModeIgnoreMaxShort)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-k",
        (char*)"ignore",
        (char*)"-K",
        (char*)"2000,2001,2002,2003,2004,2005,2006,2007,2008,2009"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_no_exit(&c_in);
    CHECK_EQUAL(IGNORE, c_in.ppid_mode);
    CHECK_EQUAL(10, c_in.ppids_len);
    for (int i = 0; i < 10; ++i) {
        CHECK_EQUAL(2000 + i, c_in.ppids[i]);
    }
}

TEST(UserArgControlGroup, TestPpidModeIgnoreMaxPlus1Short)
{
    struct control_input c_in;

    char* argv[] = {
        (char*)"test",
        (char*)"-k",
        (char*)"ignore",
        (char*)"-K",
        (char*)"2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010"
    };
    int argc = sizeof(argv) / sizeof(char*);
    user_args_control_parse(&c_in, argc, argv);
    check_parse_state_exit_error(&c_in);
}

int main(int argc, char** argv)
{
    const char* verboseArgv[] = { argv[0], "-v" };
    return CommandLineTestRunner::RunAllTests(2, verboseArgv);
}