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

#include "user/jsonify/control.h"

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

static int parse_user_input(struct control_input *input, int argc, char *argv[])
{
    return user_args_control_must_parse_control_input(
        input, argc, argv
    );
}

static int update_control_input_map(struct control_input *input)
{
    int update_flags;

    update_flags = BPF_ANY;
    // update_flags |= BPF_F_LOCK;

    int key = 0;
    int ret = bpf_map__update_elem(
        skel->maps.control_input_map, 
        &key, sizeof(key),
        input, sizeof(struct control_input),
        update_flags
    );

    return ret;
}

static int get_control_input_from_map(struct control_input *result)
{
    int lookup_flags;
    lookup_flags = BPF_ANY;
    // lookup_flags |= BPF_F_LOCK;

    int key = 0;
    int ret = bpf_map__lookup_elem(
        skel->maps.control_input_map, 
        &key, sizeof(key),
        result, sizeof(struct control_input),
        lookup_flags
    );
    return ret;
}

static void print_current_control_input()
{
    struct control_input result;
    int dst_len = 512;
    char dst[dst_len];

    if (get_control_input_from_map(&result) != 0)
    {
        printf("Failed to get control input entry from map\n");
        return;
    }

    struct json_buffer s;
    jsonify_core_init(&s, dst, dst_len);
    jsonify_core_open_obj(&s);

    jsonify_control_write_control_input(&s, &result);

    jsonify_core_close_obj(&s);

    printf("Control Input set in EBPF map:\n");
    printf("%s\n", dst);
}

int main(int argc, char *argv[])
{
    int result;
    struct ring_buffer *ringbuf = NULL;
    int err, ringbuf_map_fd;
    struct control_input input;
    
    result = parse_user_input(&input, argc, argv);

    if (result != 0)
    {
        return result;
    }

    syslog(LOG_INFO, "%s : Registering signal handler...\n", log_prefix);
    signal(SIGTERM, sig_handler);

    skel = ameba__open_and_load();
    if (!skel)
    {
        syslog(LOG_ERR, "%s : Failed to load bpf skeleton\n", log_prefix);
        result = 1;
        return result;
    }

    result = update_control_input_map(&input);
    if (result != 0)
    {
        syslog(LOG_ERR, "%s : Error updaing control input\n", log_prefix);
        result = 1;
        goto skel_destroy;
    }

    print_current_control_input();

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
