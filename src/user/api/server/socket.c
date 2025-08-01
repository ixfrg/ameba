// SPDX-License-Identifier: GPL-3.0-or-later
/*
AMEBA - A Minimal eBPF-based Audit: an eBPF-based Linux telemetry collection tool.
Copyright (C) 2025  Hassaan Irshad

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>

#include "user/helper/log.h"
#include "user/helper/lock.h"
#include "user/helper/ring_buffer.h"
#include "user/api/server/socket.h"
#include "user/api/handle.h"


static struct {
    volatile int shutdown;
    volatile int running;
    volatile struct ring_buffer *rb;
} global_state = {
    .shutdown = 0,
    .running = 0
};


static void handle_request(int client_fd, char *req, uint32_t req_len)
{
    uint32_t resp_len;
    void *resp = NULL;
    int ret = api_handle(req, req_len, &resp, &resp_len);
    if (ret == 0)
    {
        ssize_t bytes_written = write(client_fd, resp, resp_len);
        if (bytes_written == -1)
        {
            log_state_msg(
                APP_STATE_OPERATIONAL_WITH_ERROR,
                "Failed handle_request. Failed to write response to client. Err: %s", strerror(errno)
            );
        }
    } else
    {
        log_state_msg(
            APP_STATE_OPERATIONAL_WITH_ERROR,
            "Failed handle_request. Silently discarded data"
        );
    }
}

static int handle_data(int client_fd, struct ring_buffer *rb, char *data, uint64_t data_len)
{
    if (!rb || data_len <= 0)
        return -1;

    if (!ring_buffer_push(rb, data, data_len))
    {
        // TODO... just increase the buffer size.
        log_state_msg(
            APP_STATE_OPERATIONAL_WITH_ERROR,
            "Failed handle_data. ring_buffer overflow."
        );
        return -1;
    }

    while (1)
    {
        uint32_t api_request_len;

        if (!ring_buffer_peek(rb, (char *)&api_request_len, sizeof(api_request_len)))
        {
            break;
        }

        // Check for max len! TODO

        uint64_t available = ring_buffer_available_capacity(rb);
        if (available < api_request_len + sizeof(api_request_len))
        {
            // Required amount of data not available.
            // Wait for it on the next go.
            break;
        }

        // Discard the len field
        ring_buffer_discard(rb, sizeof(api_request_len));

        char *req_buf = malloc(api_request_len);
        if (!req_buf) {
            log_state_msg(
                APP_STATE_OPERATIONAL_WITH_ERROR,
                "Failed handle_data. Could not malloc buffer for request"
            );
            return -1;
        }

        ring_buffer_pop(rb, req_buf, api_request_len);

        handle_request(client_fd, req_buf, api_request_len);

        free(req_buf);
    }

    return 0;
}

/*
    Returns:
        -1   => Error
        +ive => File descriptor
*/
static int open_api_server_socket(char *unix_socket_path)
{
    int fd;
    struct sockaddr_un addr;


    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to create api server socket. Err: %s", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, unix_socket_path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) == -1) {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to bind api server socket. Err: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 1) == -1) {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to listen to api server socket. Err: %s", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

int api_server_socket_stop()
{
    global_state.shutdown = 1;
    return 0;
}

int api_server_socket_is_running()
{
    return global_state.running == 0 ? 0 : 1;
}

int api_server_socket_start(char *unix_socket_path)
{
    uint32_t buf_len = 1024;
    char buf[buf_len];

    int result = 0;
    int client_fd = -1;
    int server_fd = -1;

    if (global_state.running == 1)
    {
        log_state_msg(APP_STATE_OPERATIONAL_WITH_ERROR, "Failed to start api server socket. Err: Already running");
        result = -1;
        goto cleanup;
    }

    global_state.running = 1;
    global_state.rb = ring_buffer_alloc(buf_len);
    if (!global_state.rb)
    {
        log_state_msg(APP_STATE_OPERATIONAL_WITH_ERROR, "Failed to alloc ring buffer");
        result = -1;
        goto cleanup;
    }

    server_fd = open_api_server_socket(unix_socket_path);
    if (server_fd == -1)
    {
        result = -1;
        goto cleanup;
    }

    fd_set accept_fds;
    FD_ZERO(&accept_fds);
    FD_SET(server_fd, &accept_fds);

    struct timeval accept_timeout = {
        .tv_sec = 5,
        .tv_usec = 0
    };

    while (1)
    {
        if (global_state.shutdown)
            goto cleanup;

        int select_ret = select(server_fd + 1, &accept_fds, NULL, NULL, &accept_timeout);
        if (select_ret < 0)
        {
            log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to select accept client on api server socket. Err: %s", strerror(errno));
            result = -1;
            goto cleanup;
        } else if (select_ret == 0)
        {
            continue;
        }

        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0)
        {
            log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to accept client on api server socket. Err: %s", strerror(errno));
            result = -1;
            goto cleanup;
        }

        log_state_msg(APP_STATE_OPERATIONAL, "API server socket client opened");

        while (1)
        {
            if (global_state.shutdown)
                goto cleanup;

            errno = 0;
            ssize_t bytes_read = read(client_fd, &buf[0], buf_len);
            if (bytes_read > 0)
            {
                int handle_data_result = handle_data(client_fd, (struct ring_buffer *)global_state.rb, &buf[0], (uint64_t)bytes_read);
                if (handle_data_result != 0)
                {
                    // forcefully close the connection, and clear the buffer.
                    log_state_msg(APP_STATE_OPERATIONAL, "Forcefully closed API server socket client. Invalid data.");
                    close(client_fd);
                    client_fd = -1;
                    ring_buffer_clear((struct ring_buffer *)global_state.rb);
                    break;
                }
            } else if (bytes_read == 0)
            {
                log_state_msg(APP_STATE_OPERATIONAL, "API server socket client closed");
                break;
            } else
            {
                if (errno == EINTR)
                {
                    continue;
                }
                break;
            }
        }
    }

cleanup:
    if (server_fd != -1)
        close(server_fd);
    if (client_fd != -1)
        close(client_fd);
    if (global_state.rb != NULL)
        ring_buffer_free((struct ring_buffer *)global_state.rb);
    global_state.rb = NULL;
    global_state.running = 0;
    global_state.shutdown = 0;
    return result;
}