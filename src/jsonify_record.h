#pragma once

#include "record.h"

#define MAX_BUFFER_LEN 1024

struct str_buffer_state
{
    char *buf;
    int bufIdx;
    int maxBufLen;
    int remBufLen;
};


int record_data_to_json(char *dst, unsigned int dst_len, void *data, size_t data_len);