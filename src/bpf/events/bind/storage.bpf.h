#pragma once

#include "common/vmlinux.h"

#include "common/types.h"


int bind_storage_insert(struct record_bind *r_bind);
int bind_storage_set(int fd, event_id_t event_id, struct elem_sockaddr *local_sa);
int bind_storage_output(void);
int bind_storage_delete(void);
