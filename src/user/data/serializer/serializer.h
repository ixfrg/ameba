#pragma once


/*
    A function to perform some common data conversion checks.

    1. Check if pointers are null
    2. Check if lengths are positive
    3. Check if header (i.e. elem_common) is present
    4. Check if magic value in header is correct

    It does no conversion!

    Return:
        -ive -> The error
        0    -> No error
        +ive -> Undefined
*/
long data_serializer_common(void *dst, size_t dst_len, void *data, size_t data_len);


struct data_serializer {

    /*
        Convert the 'data' to a different format.
        Put the formatted data into 'dst'.

        Return:
            +ive -> The actual size of 'dst'
            -ive -> Error
            0    -> Undefined

    */
    long (*serialize)(void *dst, size_t dst_len, void *data, size_t data_len);

};