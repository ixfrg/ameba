#pragma once

#include <stddef.h>


struct data_deserializer {

    /*
        Deserialize the data.

        Call this function until it returns a positive value.

        The positive value indicates that data size that has been successfully deserialized.

        If an error occurs then the data is discarded. It is unforgiving i.e. it discards data
        if not enough space is available.

        The return value of 0 is used to handle the case where data is being processed but not
        ready yet.

        Return:
            +ive -> The size of the data that is deserialized and ready.
            -ive -> Error and any incomplete data is discarded.
            0    -> Not ready.

    */
    int (*deserialize)(void *data, size_t data_len);

    /*
        Read the deserialized data into the given 'dst'.

        Return:
            +ive -> Data written into dst
            -ive -> Error
            0    -> Undefined
    */
    int (*read)(void *dst, int dst_len);

    /*
        Return the space available in the internal buffer.
    */
    int (*get_available_space)(void);

};