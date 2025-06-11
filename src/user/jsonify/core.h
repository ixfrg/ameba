#pragma once


#define MAX_BUFFER_LEN 1024


struct json_buffer
{
    char *buf;
    int bufIdx;
    int maxBufLen;
    int remBufLen;
    int overflown;
};


int jsonify_core_init(struct json_buffer *s, char *dst_buf, unsigned int dst_buf_len);
int jsonify_core_open_obj(struct json_buffer *s);
int jsonify_core_close_obj(struct json_buffer *s);
int jsonify_core_has_overflown(struct json_buffer *s);
int jsonify_core_write_newline(struct json_buffer *s);
int jsonify_core_get_total_chars_written(struct json_buffer *s);
int jsonify_core_write_bytes(struct json_buffer *s, const char *key, unsigned char *val, int val_size);
int jsonify_core_write_int(struct json_buffer *s, const char *key, int val);
int jsonify_core_write_uint(struct json_buffer *s, const char *key, unsigned int val);
int jsonify_core_write_str(struct json_buffer *s, const char *key, const char *val);
int jsonify_core_write_as_literal(struct json_buffer *s, const char *key, const char *val);
int jsonify_core_write_ulong(struct json_buffer *s, const char *key, unsigned long val);
int jsonify_core_write_ulonglong(struct json_buffer *s, const char *key, unsigned long long val);
int jsonify_core_write_long(struct json_buffer *s, const char *key, long val);
int jsonify_core_write_short(struct json_buffer *s, const char *key, short int val);
int jsonify_core_write_timespec64(struct json_buffer *s, const char *key, long long tv_sec, long tv_nsec);
