#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>


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


int writer_write(char *dst, int dst_len)
{
    int total = 0;
    total += write(writer_fd, dst, dst_len);
    total += write(writer_fd, "\n", 1);
    return total;
}



