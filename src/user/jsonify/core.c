#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>

#include "user/error.h"

#include "user/jsonify/core.h"


static int jsonify_core_snprintf(struct json_buffer *s, const char *format, ...)
{
    va_list args;
    int charsWritten;

    if (s->remBufLen == 0)
    {
        return 0;
    }

    va_start(args, format);

    charsWritten = vsnprintf(&(s->buf[s->bufIdx]), s->remBufLen, format, args);
    if (charsWritten >= s->remBufLen)
    {
        s->overflown = 1;
        s->remBufLen = 0;
        va_end(args);
        return charsWritten;
    }
    else
    {
        s->remBufLen -= charsWritten;
        s->bufIdx += charsWritten;
        va_end(args);
        return charsWritten;
    }
}

static int jsonify_core_write_element_divider(struct json_buffer *s)
{
    if (s->bufIdx > 1)
        return jsonify_core_snprintf(s, ",");
    return 0;
}

int jsonify_core_has_overflown(struct json_buffer *s)
{
    return s->overflown;
}

int jsonify_core_init(struct json_buffer *s, char *dst_buf, unsigned int dst_buf_len)
{
    s->buf = dst_buf;
    s->maxBufLen = dst_buf_len - 1;
    s->bufIdx = 0;
    s->remBufLen = s->maxBufLen - s->bufIdx;
    s->overflown = 0;
    memset(&(s->buf[0]), 0, s->maxBufLen);
    return 0;
}

// static int str_buffer_state_is_full(struct str_buffer_state *s){
//     return s->remBufLen == 0;
// }

int jsonify_core_open_obj(struct json_buffer *s)
{
    return jsonify_core_snprintf(s, "{");
}

int jsonify_core_close_obj(struct json_buffer *s)
{
    return jsonify_core_snprintf(s, "}");
}

int jsonify_core_write_bytes(struct json_buffer *s, const char *key, unsigned char *val, int val_size)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":\"", key);
    for (size_t i = 0; i < val_size; i++)
    {
        total += jsonify_core_snprintf(s, "%02x", val[i]);
    }
    total += jsonify_core_snprintf(s, "\"");
    return total;
}

int jsonify_core_write_int(struct json_buffer *s, const char *key, int val)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":%d", key, val);
    return total;
}

int jsonify_core_write_uint(struct json_buffer *s, const char *key, unsigned int val)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":%u", key, val);
    return total;
}

int jsonify_core_write_str(struct json_buffer *s, const char *key, const char *val)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":\"%s\"", key, val);
    return total;
}

int jsonify_core_write_raw(struct json_buffer *s, const char *key, const char *val)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":%s", key, val);
    return total;
}

int jsonify_core_write_ulong(struct json_buffer *s, const char *key, unsigned long val)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":%lu", key, val);
    return total;
}

int jsonify_core_write_long(struct json_buffer *s, const char *key, long val)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":%ld", key, val);
    return total;
}

int jsonify_core_write_timespec64(struct json_buffer *s, const char *key, long long tv_sec, long tv_nsec)
{
    int total = 0;
    total += jsonify_core_write_element_divider(s);
    total += jsonify_core_snprintf(s, "\"%s\":%llu.%03lu", key, (unsigned long long)tv_sec, tv_nsec/1000000);
    return total;
}