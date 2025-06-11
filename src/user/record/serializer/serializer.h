#pragma once

#include <sys/types.h>

#include "common/types.h"


/*
    A function to perform some common record serialization checks.

    1. Check if pointers are null
    2. Check if lengths are positive
    3. Check if header (i.e. elem_common) is present
    4. Check if magic value in header is correct

    It does no serialization!

    Return:
        -ive -> The error
        0    -> No error
        +ive -> Undefined
*/
long record_serializer_common(void *dst, size_t dst_len, struct elem_common *record, size_t record_len);


struct record_serializer {

    /*
        Serialize a record to a different format.
        Put the serialized record into 'dst'.

        Return:
            +ive -> The actual size of 'dst'
            -ive -> Error
            0    -> Undefined

    */
    long (*serialize)(void *dst, size_t dst_len, struct elem_common *record, size_t record_len);

};