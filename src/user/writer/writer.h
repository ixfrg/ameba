#pragma once

#include "common/types.h"


int writer_init();
int writer_write(struct elem_common *data, size_t data_len);
int writer_close();