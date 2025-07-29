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
#include "user/arg/parse_state.h"
#include "user/arg/common.h"
}

#include "CppUTest/TestHarness.h"

void test_helper_parse_state_must_be_exit_with_code(struct arg_parse_state *s, int expected_code)
{
    CHECK_EQUAL(1, s->exit);
    CHECK_EQUAL(expected_code, s->code);
}

void test_helper_parse_state_must_be_exit_with_negative_code(struct arg_parse_state *s)
{
    CHECK_EQUAL(1, s->exit);
    CHECK(0 > s->code);
}

void test_helper_parse_state_must_be_exit_with_zero_code(struct arg_parse_state *s)
{
    CHECK_EQUAL(1, s->exit);
    CHECK_EQUAL(0, s->code);
}

void test_helper_parse_state_must_be_not_exit(struct arg_parse_state *s)
{
    CHECK_EQUAL(0, s->exit);
    CHECK_EQUAL(0, s->code);
}

void test_helper_arg_common_must_be_show_version(struct arg_common *s)
{
    CHECK_EQUAL(1, s->show_version);
    CHECK_EQUAL(0, s->show_usage);
    CHECK_EQUAL(0, s->show_help);   
}

void test_helper_arg_common_must_be_show_usage(struct arg_common *s)
{
    CHECK_EQUAL(0, s->show_version);
    CHECK_EQUAL(1, s->show_usage);
    CHECK_EQUAL(0, s->show_help);   
}

void test_helper_arg_common_must_be_show_help(struct arg_common *s)
{
    CHECK_EQUAL(0, s->show_version);
    CHECK_EQUAL(0, s->show_usage);
    CHECK_EQUAL(1, s->show_help);   
}

void test_helper_arg_common_must_be_all_zero(struct arg_common *s)
{
    CHECK_EQUAL(0, s->show_version);
    CHECK_EQUAL(0, s->show_usage);
    CHECK_EQUAL(0, s->show_help);   
}