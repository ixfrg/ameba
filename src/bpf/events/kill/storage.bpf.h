#pragma once

#include "common/vmlinux.h"

#include "common/types.h"


int kill_storage_insert(struct record_kill *map_val);
int kill_storage_delete(void);
int kill_storage_set_props_on_sys_exit(int ret, event_id_t event_id);
pid_t kill_storage_get_target_pid(void);
int kill_storage_output(void);