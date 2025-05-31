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

#include "common/constants.h"
#include "user/convert_data.h"
#include "user/error.h"
#include "user/writer.h"
#include "user/jsonify/record.h"
#include "ameba.skel.h"

#include "user/args/control.h"


static const char *log_prefix = "[ameba] [user]";

static struct ameba *skel = NULL;


static int handle_ringbuf_data(void *ctx, void *data, size_t data_len)
{
    int dst_len = MAX_BUFFER_LEN;
    char *dst = (char *)malloc(sizeof(char) * dst_len);

    if (dst == NULL){
        return 0;
    }

    int result = convert_data_to_json(dst, dst_len, data, data_len);

    if (result >= 0)
    {
        writer_write(dst, strnlen(dst, MAX_BUFFER_LEN));
    } else {
        printf("%s : Failed 'convert_data_to_json'. Error: %d\n", log_prefix, result);
        // error
    }

    free(dst);

    return 0;
}

static void sig_handler(int sig)
{
    if (sig == SIGTERM)
    {
        syslog(LOG_INFO, "%s : Received termination signal...\n", log_prefix);
        writer_close();
        if (skel != NULL)
        {
            ameba__destroy(skel);
        }
        exit(0);
    }
}

int main(int argc, char *argv[])
{
    struct control_input input;

    return user_args_control_must_parse_control_input(
        &input, argc, argv
    ); 

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
    ringbuf_map_fd = bpf_object__find_map_fd_by_name(skel->obj, OUTPUT_RINGBUF_MAP_NAME);
    if (ringbuf_map_fd < 0)
    {
        syslog(LOG_ERR, "%s : Failed to find ring buffer map object\n", log_prefix);
        result = 1;
        goto skel_detach;
    }

    ringbuf = ring_buffer__new(ringbuf_map_fd, handle_ringbuf_data, NULL, NULL);

    int writer_error = writer_init();

    if (writer_error == -1)
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
    writer_close();

skel_detach:
    ameba__detach(skel);

skel_destroy:
    ameba__destroy(skel);

// exit:
    return result;
}
