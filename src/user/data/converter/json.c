#include <stddef.h>
#include "user/data/converter/converter.h"
#include "user/jsonify/record.h"


static long data_converter_json_convert(void *dst, size_t dst_len, void *data, size_t data_len)
{
    int err = data_converter_common(dst, dst_len, data, data_len);
    if (err != 0)
        return err;

    struct elem_common *e_common = data;

    struct json_buffer s;
    jsonify_core_init(&s, dst, dst_len);
    jsonify_core_open_obj(&s);

    int jsonify_result = jsonify_record(&s, e_common, data_len);

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


const struct data_converter data_converter_json = {
    .convert = data_converter_json_convert
};