#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include <sys/types.h>
#include "common/types.h"
#include "user/jsonify/record.h"
#include "user/error.h"


static const char * LOG_FILE_SYMLINK = "/tmp/current_ameba_log.json";


static int writer_fd;


static int create_log_file_symlink(char *src, const char *tgt)
{
    if (access(tgt, F_OK) == 0)
        if (unlink(tgt) != 0)
        {
            perror("Error removing existing symlink");
            return 1;
        }
    if (symlink(src, tgt) != 0)
    {
        perror("Error creating symlink");
        return 1;
    }
    return 0;
}


int writer_init()
{
    int fd;
    char filename[40];
    struct tm *time_str;

    time_t current_time = time(NULL);

    time_str = localtime(&current_time);
    strftime(filename, sizeof(filename), "/tmp/prov_%Y-%m-%d_%H:%M:%S.json", time_str);

    fd = open(filename, O_RDWR | O_CREAT, 0666);

    if (fd == -1)
    {
        return -1;
    }

    writer_fd = fd;

    create_log_file_symlink(&filename[0], LOG_FILE_SYMLINK);

    return 0;
}


int writer_close()
{
    return close(writer_fd);
}


static int convert_data_to_json(char *dst, int dst_len, struct elem_common *data, size_t data_len)
{
    if (dst == NULL)
        return ERR_DST_INVALID;
    if (dst_len == 0)
        return ERR_DST_INSUFFICIENT;
    if (data == NULL)
        return ERR_DATA_INVALID;
    if (data_len == 0)
        return ERR_DATA_INVALID;

    if (data_len < sizeof(struct elem_common))
        return ERR_DATA_INVALID_HEADER;

    struct elem_common *e_common = data;

    if (e_common->magic != AMEBA_MAGIC)
        return ERR_DATA_INVALID_MAGIC;

    struct json_buffer s;
    jsonify_core_init(&s, dst, dst_len);
    jsonify_core_open_obj(&s);

    int jsonify_result = jsonify_record(&s, e_common, data_len);

    jsonify_core_close_obj(&s);

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


int writer_write(struct elem_common *data, size_t data_len)
{
    int write_result = 0;

    int dst_len = MAX_BUFFER_LEN;
    char *dst = (char *)malloc(sizeof(char) * dst_len);

    if (dst == NULL){
        return 0;
    }

    int chars_written = convert_data_to_json(dst, dst_len, data, data_len);

    if (chars_written > 0)
    {
        write_result += write(writer_fd, dst, chars_written);
        write_result += write(writer_fd, "\n", 1);
    } else {
        write_result = chars_written;
    }

    free(dst);

    return write_result;
}



