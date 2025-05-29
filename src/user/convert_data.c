#include <sys/types.h>

#include "user/convert_data.h"

#include "common/types.h"
#include "user/jsonify/record.h"
#include "user/error.h"


int convert_data_to_json(char *dst, unsigned int dst_len, void *data, size_t data_len)
{
    if (dst == NULL)
        return ERR_DST_INVALID;
    if (dst_len == 0)
        return ERR_DST_INSUFFICIENT;
    if (data == NULL)
        return ERR_DATA_INVALID;
    if (data_len == 0)
        return ERR_DATA_INVALID;

    if (data_len < sizeof(struct elem_common))
        return ERR_DATA_INVALID_HEADER;

    struct elem_common *e_common = (struct elem_common *)(data);

    if (e_common->magic != AMEBA_MAGIC)
        return ERR_DATA_INVALID_MAGIC;

    struct json_buffer s;
    jsonify_core_init(&s, dst, dst_len);
    jsonify_core_open_obj(&s);

    switch (e_common->record_type)
    {
        case RECORD_TYPE_CONNECT:
            if (data_len != sizeof(struct record_connect))
                return ERR_DATA_SIZE_MISMATCH;
            jsonify_record_connect(&s, (struct record_connect *)data);
            break;
        case RECORD_TYPE_ACCEPT:
            if (data_len != sizeof(struct record_accept))
                return ERR_DATA_SIZE_MISMATCH;
            jsonify_record_accept(&s, (struct record_accept *)data);
            break;
        case RECORD_TYPE_NAMESPACE:
            if (data_len != sizeof(struct record_namespace))
                return ERR_DATA_SIZE_MISMATCH;
            jsonify_record_namespace(&s, (struct record_namespace *)data);
            break;
        case RECORD_TYPE_NEW_PROCESS:
            if (data_len != sizeof(struct record_new_process))
                return ERR_DATA_SIZE_MISMATCH;
            jsonify_record_new_process(&s, (struct record_new_process *)data);
            break;
        case RECORD_TYPE_CRED:
            if (data_len != sizeof(struct record_cred))
                return ERR_DATA_SIZE_MISMATCH;
            jsonify_record_cred(&s, (struct record_cred *)data);
            break;
        case RECORD_TYPE_SEND:
            if (data_len != sizeof(struct record_send))
                return ERR_DATA_SIZE_MISMATCH;
            jsonify_record_send(&s, (struct record_send *)data);
            break;
        default:
            // Quietly ignore any expected record.
            return ERR_DATA_UNKNOWN;
    }

    jsonify_core_close_obj(&s);

    if (jsonify_core_has_overflown(&s)){
        return ERR_DST_INSUFFICIENT;
    }

    return 0;
}