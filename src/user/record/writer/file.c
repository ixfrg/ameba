#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/types.h>

#include "user/record/writer/writer.h"


static char filepath[PATH_MAX];
static int data_writer_file_fd = -1;


static int record_writer_file_set_init_args(void *ptr, size_t ptr_len)
{
    if (!ptr)
        return -1;
    
    if (ptr_len >= PATH_MAX)
        return -1;

    memcpy(&filepath[0], ptr, ptr_len);
    return 0;
}

static int record_writer_file_init()
{
    char *fpath = &filepath[0];

    int fd;

    fd = open(fpath, O_RDWR | O_CREAT | O_TRUNC, 0666);

    if (fd == -1)
        return -1;

    data_writer_file_fd = fd;

    return 0;
}

static int record_writer_file_close()
{
    close(data_writer_file_fd);
    data_writer_file_fd = -1;
    memset(&filepath[0], 0, PATH_MAX);
    return 0;
}

static int record_writer_file_write(struct elem_common *record, size_t record_len)
{
    if (data_writer_file_fd == -1)
        return -2;
    return write(data_writer_file_fd, record, record_len);
}


const struct record_writer record_writer_file =
{
    .set_init_args = record_writer_file_set_init_args,
    .init = record_writer_file_init,
    .close = record_writer_file_close,
    .write = record_writer_file_write
};


