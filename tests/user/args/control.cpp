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
}


TEST_GROUP(UserArgControlGroup)
{
};

TEST(UserArgControlGroup, TestParse)
{
    int argc = 0;
    char* argv[] = {};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK_EQUAL(res, 0);
}

TEST(UserArgControlGroup, TestDefaults)
{
    int argc = 0;
    char* argv[] = {};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK_EQUAL(res, 0);
    
    CHECK_EQUAL(global_control_input.lock, FREE);
    CHECK_EQUAL(global_control_input.global_mode, IGNORE);
    CHECK_EQUAL(global_control_input.uid_mode, IGNORE);
    CHECK_EQUAL(global_control_input.uids_len, 0);
    CHECK_EQUAL(global_control_input.pid_mode, IGNORE);
    CHECK_EQUAL(global_control_input.pids_len, 0);
    CHECK_EQUAL(global_control_input.ppid_mode, IGNORE);
    CHECK_EQUAL(global_control_input.ppids_len, 0);
    CHECK_EQUAL(global_control_input.netio_mode, IGNORE);
}

TEST(UserArgControlGroup, TestGlobalModeCapture)
{
    int argc = 3;
    char* argv[] = {(char*)"test", (char*)"--global-mode", (char*)"capture"};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK_EQUAL(res, 0);
    CHECK_EQUAL(global_control_input.global_mode, CAPTURE);
}

TEST(UserArgControlGroup, TestGlobalModeInvalid)
{
    int argc = 3;
    char* argv[] = {(char*)"test", (char*)"--global-mode", (char*)"invalid"};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK(res != 0);
}

TEST(UserArgControlGroup, TestNetioModeCapture)
{
    int argc = 3;
    char* argv[] = {(char*)"test", (char*)"--netio-mode", (char*)"capture"};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK_EQUAL(res, 0);
    CHECK_EQUAL(global_control_input.netio_mode, CAPTURE);
}

TEST(UserArgControlGroup, TestUidModeCaptureSingle)
{
    int argc = 5;
    char* argv[] = {(char*)"test", (char*)"--uid-mode", (char*)"capture", (char*)"--uid-list", (char*)"1000"};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK_EQUAL(res, 0);
    CHECK_EQUAL(global_control_input.uid_mode, CAPTURE);
    CHECK_EQUAL(global_control_input.uids_len, 1);
    CHECK_EQUAL(global_control_input.uids[0], 1000);
}

TEST(UserArgControlGroup, TestUidModeIgnoreMultiple)
{
    int argc = 5;
    char* argv[] = {(char*)"test", (char*)"--uid-mode", (char*)"ignore", (char*)"--uid-list", (char*)"1000,1001"};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK_EQUAL(res, 0);
    CHECK_EQUAL(global_control_input.uid_mode, IGNORE);
    CHECK_EQUAL(global_control_input.uids_len, 2);
    CHECK_EQUAL(global_control_input.uids[0], 1000);
    CHECK_EQUAL(global_control_input.uids[1], 1001);
}

TEST(UserArgControlGroup, TestUidModeIgnoreMax)
{
    int argc = 5;
    char* argv[] = {(char*)"test", (char*)"--uid-mode", (char*)"ignore", (char*)"--uid-list", (char*)"1000,1001,1002,1003,1004,1005,1006,1007,1008,1009"};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK_EQUAL(res, 0);
    CHECK_EQUAL(global_control_input.uid_mode, IGNORE);
    CHECK_EQUAL(global_control_input.uids_len, 10);
    for (int i = 0; i < 10; ++i) {
        CHECK_EQUAL(global_control_input.uids[i], 1000 + i);
    }
}

TEST(UserArgControlGroup, TestUidModeIgnoreMaxPlus1)
{
    int argc = 5;
    char* argv[] = {(char*)"test", (char*)"--uid-mode", (char*)"ignore", (char*)"--uid-list", (char*)"1000,1001,1002,1003,1004,1005,1006,1007,1008,1009,1010"};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK(res != 0);
}

TEST(UserArgControlGroup, TestPidModeCaptureSingle)
{
    int argc = 5;
    char* argv[] = {(char*)"test", (char*)"--pid-mode", (char*)"capture", (char*)"--pid-list", (char*)"1234"};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK_EQUAL(res, 0);
    CHECK_EQUAL(global_control_input.pid_mode, CAPTURE);
    CHECK_EQUAL(global_control_input.pids_len, 1);
    CHECK_EQUAL(global_control_input.pids[0], 1234);
}

TEST(UserArgControlGroup, TestPidModeIgnoreMultiple)
{
    int argc = 5;
    char* argv[] = {(char*)"test", (char*)"--pid-mode", (char*)"ignore", (char*)"--pid-list", (char*)"1234,5678"};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK_EQUAL(res, 0);
    CHECK_EQUAL(global_control_input.pid_mode, IGNORE);
    CHECK_EQUAL(global_control_input.pids_len, 2);
    CHECK_EQUAL(global_control_input.pids[0], 1234);
    CHECK_EQUAL(global_control_input.pids[1], 5678);
}

TEST(UserArgControlGroup, TestPidModeIgnoreMax)
{
    int argc = 5;
    char* argv[] = {(char*)"test", (char*)"--pid-mode", (char*)"ignore", 
                    (char*)"--pid-list", (char*)"1000,1001,1002,1003,1004,1005,1006,1007,1008,1009"};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK_EQUAL(res, 0);
    CHECK_EQUAL(global_control_input.pid_mode, IGNORE);
    CHECK_EQUAL(global_control_input.pids_len, 10);
    for (int i = 0; i < 10; ++i) {
        CHECK_EQUAL(global_control_input.pids[i], 1000 + i);
    }
}

TEST(UserArgControlGroup, TestPidModeIgnoreMaxPlus1)
{
    int argc = 5;
    char* argv[] = {(char*)"test", (char*)"--pid-mode", (char*)"ignore", 
                    (char*)"--pid-list", (char*)"1000,1001,1002,1003,1004,1005,1006,1007,1008,1009,1010"};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK(res != 0);
}

TEST(UserArgControlGroup, TestPpidModeCaptureSingle)
{
    int argc = 5;
    char* argv[] = {(char*)"test", (char*)"--ppid-mode", (char*)"capture", (char*)"--ppid-list", (char*)"4321"};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK_EQUAL(res, 0);
    CHECK_EQUAL(global_control_input.ppid_mode, CAPTURE);
    CHECK_EQUAL(global_control_input.ppids_len, 1);
    CHECK_EQUAL(global_control_input.ppids[0], 4321);
}

TEST(UserArgControlGroup, TestPpidModeIgnoreMultiple)
{
    int argc = 5;
    char* argv[] = {(char*)"test", (char*)"--ppid-mode", (char*)"ignore", (char*)"--ppid-list", (char*)"4321,8765"};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK_EQUAL(res, 0);
    CHECK_EQUAL(global_control_input.ppid_mode, IGNORE);
    CHECK_EQUAL(global_control_input.ppids_len, 2);
    CHECK_EQUAL(global_control_input.ppids[0], 4321);
    CHECK_EQUAL(global_control_input.ppids[1], 8765);
}

TEST(UserArgControlGroup, TestPpidModeIgnoreMax)
{
    int argc = 5;
    char* argv[] = {(char*)"test", (char*)"--ppid-mode", (char*)"ignore", 
                    (char*)"--ppid-list", (char*)"2000,2001,2002,2003,2004,2005,2006,2007,2008,2009"};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK_EQUAL(res, 0);
    CHECK_EQUAL(global_control_input.ppid_mode, IGNORE);
    CHECK_EQUAL(global_control_input.ppids_len, 10);
    for (int i = 0; i < 10; ++i) {
        CHECK_EQUAL(global_control_input.ppids[i], 2000 + i);
    }
}

TEST(UserArgControlGroup, TestPpidModeIgnoreMaxPlus1)
{
    int argc = 5;
    char* argv[] = {(char*)"test", (char*)"--ppid-mode", (char*)"ignore", 
                    (char*)"--ppid-list", (char*)"2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010"};
    int res = user_args_control_must_parse_control_input(argc, argv);
    CHECK(res != 0);
}

int main(int argc, char** argv)
{
    const char* verboseArgv[] = { argv[0], "-v" };
    return CommandLineTestRunner::RunAllTests(2, verboseArgv);
}