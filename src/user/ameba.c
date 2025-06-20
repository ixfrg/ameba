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
#include <sys/types.h>

#include "common/types.h"

#include "user/args/control.h"
#include "user/args/user.h"
#include "user/jsonify/control.h"
#include "user/jsonify/user.h"
#include "common/constants.h"
#include "user/error.h"

#include "user/record/serializer/serializer.h"
#include "user/record/writer/writer.h"

#include "ameba.skel.h"


extern const struct record_serializer record_serializer_json;
extern const struct record_writer record_writer_file;
extern const struct record_writer record_writer_net;

//

static const char *log_prefix = "[ameba] [user]";

static const struct record_serializer *default_record_serializer;
static const struct record_writer *default_record_writer;

static struct ameba *skel = NULL;


static int select_default_output_writer(
    struct user_input *input,
    void **o_writer_args_ptr,
    size_t *o_writer_args_ptr_size
)
{
    switch (input->o_type)
    {
        case OUTPUT_FILE:
            *o_writer_args_ptr = &(input->output_file);
            *o_writer_args_ptr_size = sizeof(input->output_file);
            default_record_writer = &record_writer_file;
            return 0;
        case OUTPUT_NET:
            *o_writer_args_ptr = &(input->output_net);
            *o_writer_args_ptr_size = sizeof(input->output_net);
            default_record_writer = &record_writer_net;
            return 0;
        default:
            return 1;
    }
}


static int select_default_record_serializer()
{
    default_record_serializer = &record_serializer_json;
    return 0;
}


static int init_output_writer(struct user_input *input){
    void *record_writer_init_args = NULL;
    size_t record_writer_init_args_size = 0;
    
    int err = select_default_output_writer(input, &record_writer_init_args, &record_writer_init_args_size);
    if (err)
    {
        syslog(LOG_ERR, "%s : Error selecting a valid output writer\n", log_prefix);
        return -1;
    }

    err = select_default_record_serializer();
    if (err)
    {
        syslog(LOG_ERR, "%s : Error selecting a valid record serializer\n", log_prefix);
        return -1;
    }

    err = default_record_writer->set_init_args(
        record_writer_init_args, record_writer_init_args_size
    );
    if (err != 0)
    {
        syslog(LOG_ERR, "%s : Error setting init args for the output writer\n", log_prefix);
        return -1;
    }

    err = default_record_writer->init();
    if (err != 0)
    {
        syslog(LOG_ERR, "%s : Error initing output writer\n", log_prefix);
        return -1;
    }
    return 0;
}

static void close_output_writer()
{
    default_record_writer->close();
}

static int handle_ringbuf_data(void *ctx, void *data, size_t data_len)
{
    size_t dst_len = MAX_BUFFER_LEN;
    void *dst = malloc(sizeof(char) * dst_len);
    if (!dst)
        goto exit;

    long data_copied_to_dst = default_record_serializer->serialize(dst, dst_len, data, data_len);
    if (data_copied_to_dst <= 0)
    {
        printf("%s : Failed data conversion. Error: %lu\n", log_prefix, data_copied_to_dst);
        goto free_dst;
    }

    int write_result = default_record_writer->write(dst, data_copied_to_dst);
    if (write_result < 0)
    {
        printf("%s : Failed data write. Error: %d\n", log_prefix, write_result);
        goto free_dst;
    }

free_dst:
    free(dst);
exit:
    return 0;
}

static void sig_handler(int sig)
{
    if (sig == SIGTERM)
    {
        syslog(LOG_INFO, "%s : Received termination signal...\n", log_prefix);
        close_output_writer();
        if (skel != NULL)
        {
            ameba__destroy(skel);
        }
        exit(0);
    }
}

static int parse_user_input(struct user_input *input, int argc, char *argv[])
{
    int ret = user_args_user_must_parse_user_input(argc, argv);
    if(ret == 0){
        memcpy(input, &global_user_input, sizeof(*input));
    }
    return ret;
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

static void print_user_input(struct user_input *user_input)
{
    int dst_len = 1024;
    char dst[dst_len];

    struct json_buffer s;
    jsonify_core_init(&s, dst, dst_len);
    jsonify_core_open_obj(&s);

    jsonify_user_write_user_input(&s, user_input);

    jsonify_core_close_obj(&s);

    printf("User input: %s\n", dst);
}

int main(int argc, char *argv[])
{
    int result;
    struct ring_buffer *ringbuf = NULL;
    int err, ringbuf_map_fd;
    struct user_input input;
    
    result = parse_user_input(&input, argc, argv);

    if (result != 0)
    {
        return result;
    }

    print_user_input(&input);

    syslog(LOG_INFO, "%s : Registering signal handler...\n", log_prefix);
    signal(SIGTERM, sig_handler);

    skel = ameba__open_and_load();
    if (!skel)
    {
        syslog(LOG_ERR, "%s : Failed to load bpf skeleton\n", log_prefix);
        result = 1;
        return result;
    }

    result = update_control_input_map(&input.c_in);
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

    int writer_error = init_output_writer(&input);
    if (writer_error != 0)
    {
        syslog(LOG_ERR, "%s : Error creating output writer\n", log_prefix);
        result = 1;
        goto skel_detach;
    }

    printf("%s : Started\n", log_prefix);

    while (ring_buffer__poll(ringbuf, -1) >= 0)
    {
        // collect prov in callback
    }

// log_file_close:
    close_output_writer();

skel_detach:
    ameba__detach(skel);

skel_destroy:
    ameba__destroy(skel);

// exit:
    return result;
}
