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
#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

extern "C" {
#include "user/helper/ring_buffer.h"
}

TEST_GROUP(TestGroupRingBuffer)
{
    struct ring_buffer *rb;

    void setup()
    {
        rb = ring_buffer_alloc(8); // 8 usable bytes (9 total)
        CHECK(rb != NULL);
    }

    void teardown()
    {
        ring_buffer_free(rb);
    }
};

TEST(TestGroupRingBuffer, InitiallyEmpty)
{
    CHECK_TRUE(ring_buffer_is_empty(rb));
    CHECK_FALSE(ring_buffer_is_full(rb));
    LONGS_EQUAL(8, ring_buffer_available_capacity(rb));
}

TEST(TestGroupRingBuffer, PushAndPopOneByte)
{
    char in = 'A';
    char out = 0;

    CHECK_TRUE(ring_buffer_push(rb, &in, 1));
    CHECK_FALSE(ring_buffer_is_empty(rb));
    LONGS_EQUAL(7, ring_buffer_available_capacity(rb));

    CHECK_TRUE(ring_buffer_pop(rb, &out, 1));
    CHECK_TRUE(ring_buffer_is_empty(rb));
    LONGS_EQUAL('A', out);
}

TEST(TestGroupRingBuffer, PushUntilFull)
{
    char data[8] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H' };
    CHECK_TRUE(ring_buffer_push(rb, data, 8));
    CHECK_TRUE(ring_buffer_is_full(rb));
    CHECK_FALSE(ring_buffer_push(rb, data, 1));
}

TEST(TestGroupRingBuffer, PopUntilEmpty)
{
    char in[4] = {'X', 'Y', 'Z', 'W'};
    char out[4];

    CHECK_TRUE(ring_buffer_push(rb, in, 4));
    CHECK_TRUE(ring_buffer_pop(rb, out, 4));

    MEMCMP_EQUAL(in, out, 4);
    CHECK_TRUE(ring_buffer_is_empty(rb));
}

TEST(TestGroupRingBuffer, WrapAroundPushPop)
{
    char in1[5] = { 'H', 'E', 'L', 'L', 'O' };
    char in2[3] = { 'X', 'Y', 'Z' };
    char out1[5], out2[3];

    CHECK_TRUE(ring_buffer_push(rb, in1, 5));
    CHECK_TRUE(ring_buffer_pop(rb, out1, 5));
    MEMCMP_EQUAL(in1, out1, 5);

    CHECK_TRUE(ring_buffer_push(rb, in2, 3));
    CHECK_TRUE(ring_buffer_pop(rb, out2, 3));
    MEMCMP_EQUAL(in2, out2, 3);
}

int main(int argc, char **argv)
{
    const char *verboseArgv[] = { argv[0], "-v" };
    return CommandLineTestRunner::RunAllTests(2, verboseArgv);
}