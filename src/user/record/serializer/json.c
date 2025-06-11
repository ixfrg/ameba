#include <stddef.h>
#include "user/error.h"
#include "user/record/serializer/serializer.h"
#include "user/jsonify/record.h"


static long record_serializer_json_serialize(void *dst, size_t dst_len, struct elem_common *record, size_t record_len)
{
    int err = record_serializer_common(dst, dst_len, record, record_len);
    if (err != 0)
        return err;

    int write_interpreted = 0;

    struct json_buffer s;
    jsonify_core_init(&s, dst, dst_len);
    jsonify_core_open_obj(&s);

    int jsonify_result = jsonify_record(&s, record, record_len, write_interpreted);

    jsonify_core_close_obj(&s);

    jsonify_core_write_newline(&s);

    if (jsonify_result < 0)
    {
        return jsonify_result;
    }

    if (jsonify_core_has_overflown(&s))
    {
        return ERR_DST_INSUFFICIENT;
    }

    return jsonify_core_get_total_chars_written(&s);
}


const struct record_serializer record_serializer_json = {
    .serialize = record_serializer_json_serialize
};