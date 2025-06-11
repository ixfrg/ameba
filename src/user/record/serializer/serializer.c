#include <stddef.h>
#include <sys/types.h>

#include "user/error.h"
#include "common/types.h"
#include "user/record/serializer/serializer.h"


long record_serializer_common(void *dst, size_t dst_len, struct elem_common *record, size_t record_len)
{
    if (dst == NULL)
        return ERR_DST_INVALID;
    if (dst_len <= 0)
        return ERR_DST_INSUFFICIENT;
    if (record == NULL)
        return ERR_RECORD_INVALID;
    if (record_len <= 0)
        return ERR_RECORD_INVALID;

    if (record_len < sizeof(struct elem_common))
        return ERR_RECORD_INVALID_HEADER;

    if (record->magic != AMEBA_MAGIC)
        return ERR_RECORD_INVALID_MAGIC;

    return 0;
}