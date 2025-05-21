#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <bpf/bpf.h>
#include <pthread.h>
#include <netinet/in.h>
#include <syslog.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>

#include "record.h"
#include "jsonify_record.h"
#include "ameba.skel.h"


static const char *log_prefix = "[ameba] [core]";

static struct ameba *skel = NULL;

static int log_file_fd;
static char *log_file_symlink_path = "/tmp/current_ameba_log.json";


static void sig_handler(int sig)
{
    if (sig == SIGTERM)
    {
        syslog(LOG_INFO, "%s : Received termination signal...\n", log_prefix);
        close(log_file_fd);
        if (skel != NULL)
        {
            ameba__destroy(skel);
        }
        exit(0);
    }
}

static int create_log_file_symlink(char *src, char *tgt)
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

static int init_log_file()
{
    int fd;
    char filename[40];
    struct tm *time_str;

    time_t current_time = time(NULL);

    time_str = localtime(&current_time);
    strftime(filename, sizeof(filename), "/tmp/prov_%Y-%m-%d_%H:%M:%S.json", time_str);

    fd = open(filename, O_RDWR | O_CREAT);

    create_log_file_symlink(&filename[0], log_file_symlink_path);

    return fd;
}

int process_ringbuf_record(void *ctx, void *data, size_t data_len)
{
    int dst_len = MAX_BUFFER_LEN;
    char *dst = (char *)malloc(sizeof(char) * dst_len);

    if (dst == NULL){
        return 0;
    }

    int result = record_data_to_json(dst, dst_len, data, data_len);

    if (result > 0)
    {
        write(log_file_fd, dst, strnlen(dst, MAX_BUFFER_LEN));
        write(log_file_fd, "\n", 1);
    }

    free(dst);

    return 0;
}

int main(int argc, char *argv[])
{
    int result;
    struct ring_buffer *ringbuf = NULL;
    int err, ringbuf_map_fd;

    result = 0;

    syslog(LOG_INFO, "%s : Registering signal handler...\n", log_prefix);
    signal(SIGTERM, sig_handler);

    

    skel = ameba__open_and_load();
    if (!skel)
    {
        syslog(LOG_ERR, "%s : Failed to load bpf skeleton\n", log_prefix);
        result = 1;
        return result;
    }

    err = ameba__attach(skel);
    if (err != 0)
    {
        syslog(LOG_ERR, "%s : Error attaching skeleton\n", log_prefix);
        result = 1;
        goto skel_destroy;
    }

    // Locate ring buffer
    ringbuf_map_fd = bpf_object__find_map_fd_by_name(skel->obj, "ameba_ringbuf");
    if (ringbuf_map_fd < 0)
    {
        syslog(LOG_ERR, "%s : Failed to find ring buffer map object\n", log_prefix);
        result = 1;
        goto skel_detach;
    }

    ringbuf = ring_buffer__new(ringbuf_map_fd, process_ringbuf_record, NULL, NULL);

    log_file_fd = init_log_file();

    if (log_file_fd < 0)
    {
        syslog(LOG_ERR, "%s : Error creating log file\n", log_prefix);
        result = 1;
        goto skel_detach;
    }

    printf("%s : Started\n", log_prefix);

    while (ring_buffer__poll(ringbuf, -1) >= 0)
    {
        // collect prov in callback
    }

// log_file_close:
    close(log_file_fd);

skel_detach:
    ameba__detach(skel);

skel_destroy:
    ameba__destroy(skel);

// exit:
    return result;
}
