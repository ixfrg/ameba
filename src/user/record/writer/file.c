#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>

#include "user/record/writer/writer.h"
#include "user/types.h"


static struct {
    int fd;
    int initialized;
    struct output_file init_args;
} state = {0};


static int set_init_args_file(void *ptr, size_t ptr_len) {
    if (ptr_len != sizeof(struct output_file))
        return -1;

    struct output_file *in = (struct output_file *)ptr;

    if (strlen(in->path) == 0 || strlen(in->path) >= PATH_MAX)
        return -1;

    memcpy(&state.init_args, in, sizeof(struct output_file));
    return 0;
}

static int init_file() {
    if (state.initialized)
        return 0;

    state.fd = open(state.init_args.path, O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (state.fd == -1)
        return -1;

    state.initialized = 1;
    return 0;
}

static int close_file() {
    if (state.initialized) {
        close(state.fd);
        state.fd = 0;
        state.initialized = 0;
    }
    return 0;
}

static int write_file(void *data, size_t data_len) {
    if (!state.initialized)
        return -2;

    size_t written = write(state.fd, data, data_len);
    if (written != data_len)
        return -1;

    return (int)written;
}

const struct record_writer record_writer_file = {
    .set_init_args = set_init_args_file,
    .init = init_file,
    .close = close_file,
    .write = write_file,
};