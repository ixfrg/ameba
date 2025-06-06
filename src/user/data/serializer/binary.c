#include <stddef.h>
#include <string.h>
#include "user/error.h"
#include "user/data/serializer/serializer.h"


static long data_serializer_binary_serialize(void *dst, size_t dst_len, void *data, size_t data_len)
{
    int err = data_serializer_common(dst, dst_len, data, data_len);
    if (err != 0)
        return err;

    /*
        Required size:
            First 'sizeof(size_t)' bytes contain the size of the data.
            The remaining bytes are the data itself.
    */
    size_t required_size = sizeof(size_t) + data_len;
    if (required_size > dst_len)
        return ERR_DST_INSUFFICIENT;

    unsigned char *dst_c = (unsigned char *)dst;
    long i = 0;

    memcpy(&dst_c[i], &data_len, sizeof(size_t));
    i += sizeof(size_t);
    memcpy(&dst_c[i], data, data_len);
    i += data_len;

    return i;
}


const struct data_serializer data_serializer_binary = {
    .serialize = data_serializer_binary_serialize
};