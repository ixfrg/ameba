#include <stdlib.h>
#include <stdio.h>
#include "user/jsonify/types.h"
#include "user/jsonify/control.h"
#include "user/jsonify/user.h"


int jsonify_user_write_output_file(struct json_buffer *s, struct output_file *o_file)
{
    int s_child_buf_size = PATH_MAX + 50;
    char s_child_buf[s_child_buf_size];
    struct json_buffer s_child;
    jsonify_core_init(&s_child, &(s_child_buf[0]), s_child_buf_size);
    jsonify_core_open_obj(&s_child);
    jsonify_core_write_str(&s_child, "path", o_file->path);
    jsonify_core_close_obj(&s_child);

    int total = 0;
    total = jsonify_core_write_as_literal(s, "output_file", &s_child.buf[0]);
    return total;
}

int jsonify_user_write_output_net(struct json_buffer *s, struct output_net *o_net)
{
    int s_child_buf_size = 256;
    char s_child_buf[s_child_buf_size];
    struct json_buffer s_child;
    jsonify_core_init(&s_child, &(s_child_buf[0]), s_child_buf_size);
    jsonify_core_open_obj(&s_child);
    jsonify_core_write_str(&s_child, "ip", o_net->ip);
    jsonify_core_write_int(&s_child, "port", o_net->port);
    jsonify_types_write_ip_family_name(&s_child, "ip_family", o_net->ip_family);
    jsonify_core_close_obj(&s_child);


    int total = 0; 
    total += jsonify_core_write_as_literal(s, "output_net", &s_child.buf[0]);
    return total;
}

int jsonify_user_write_output(struct json_buffer *s, struct user_input *val)
{
    int total = 0;
    char *v;
    switch (val->o_type)
    {
        case OUTPUT_NONE:
            v = "none";
            break;
        case OUTPUT_FILE:
            total += jsonify_user_write_output_file(s, &(val->output_file));
            v = "file";
            break;
        case OUTPUT_NET:
            total += jsonify_user_write_output_net(s, &(val->output_net));
            v = "net";
            break;
        default:
            v = "unknown";
            break;
    }
    total += jsonify_core_write_str(s, "output_type", v);
    return total;
}

int jsonify_user_write_user_input(struct json_buffer *s, struct user_input *val)
{
    int s_child_buf_size = 256;
    char s_child_buf[s_child_buf_size];
    struct json_buffer s_child;
    jsonify_core_init(&s_child, &(s_child_buf[0]), s_child_buf_size);
    jsonify_core_open_obj(&s_child);
    jsonify_control_write_control_input(&s_child, &(val->c_in));
    jsonify_core_close_obj(&s_child);

    int total = 0;
    total = jsonify_core_write_as_literal(s, "control_input", &s_child.buf[0]);
    total += jsonify_user_write_output(s, val);
    return total;
}