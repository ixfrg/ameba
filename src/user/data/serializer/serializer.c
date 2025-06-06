#include <stddef.h>
#include <sys/types.h>

#include "user/error.h"
#include "common/types.h"
#include "user/data/serializer/serializer.h"


long data_serializer_common(void *dst, size_t dst_len, void *data, size_t data_len)
{
    if (dst == NULL)
        return ERR_DST_INVALID;
    if (dst_len <= 0)
        return ERR_DST_INSUFFICIENT;
    if (data == NULL)
        return ERR_DATA_INVALID;
    if (data_len <= 0)
        return ERR_DATA_INVALID;

    if (data_len < sizeof(struct elem_common))
        return ERR_DATA_INVALID_HEADER;

    struct elem_common *e_common = data;

    if (e_common->magic != AMEBA_MAGIC)
        return ERR_DATA_INVALID_MAGIC;

    return 0;
}