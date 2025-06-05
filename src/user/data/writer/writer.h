#pragma once

#include <stddef.h>
#include "common/types.h"


struct data_writer
{
    /*
        Function to set arguments to used in 'init' function.

        Return:
            -ive => Invalid argument 
            0    => Success
    */
    int (*set_init_args) (void *ptr, size_t ptr_len);
    /*
        Function to initialize the writer.

        Return:
            -ive => Failure
            0    => Success
    */
    int (*init) ();
    /*
        Function to close the writer.

        Return:
            Not handled.
    */
    int (*close) ();
    /*
        Write the given data to the writer.

        Return:
            -2  => The writer is not initialized
            -1  => The underlying write failed
            >=0 => The bytes written
    */
    int (*write) (void* data, size_t data_len);
};
