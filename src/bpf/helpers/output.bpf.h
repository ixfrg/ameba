#pragma once

/*

    A module for defining helper functions for outputting BPF records.

*/

#include "common/types.h"

/*
    Write record_cred to output ring buffer.

    Return:
        See 'bpf_ringbuf_output'.
*/
long output_record_cred(struct record_cred *ptr);

/*
    Write record_namespace to output ring buffer.

    Return:
        See 'bpf_ringbuf_output'.
*/
long output_record_namespace(struct record_namespace *ptr);

/*
    Write record_new_process to output ring buffer.

    Return:
        See 'bpf_ringbuf_output'.
*/
long output_record_new_process(struct record_new_process *ptr);

/*
    Write record_accept to output ring buffer.

    Return:
        See 'bpf_ringbuf_output'.
*/
long output_record_accept(struct record_accept *ptr);

/*
    Write record_bind to output ring buffer.

    Return:
        See 'bpf_ringbuf_output'.
*/
long output_record_bind(struct record_bind *ptr);

/*
    Write record_kill to output ring buffer.

    Return:
        See 'bpf_ringbuf_output'.
*/
long output_record_kill(struct record_kill *ptr);

/*
    Write record_send_recv to output ring buffer.

    Return:
        See 'bpf_ringbuf_output'.
*/
long output_record_send_recv(struct record_send_recv *ptr);

/*
    Write record_connect to output ring buffer.

    Return:
        See 'bpf_ringbuf_output'.
*/
long output_record_connect(struct record_connect *ptr);

/*
    Write record_audit_log_exit to output ring buffer.

    Return:
        See 'bpf_ringbuf_output'.
*/
long output_record_audit_log_exit(struct record_audit_log_exit *ptr);
// long output_record_as_dynptr(struct bpf_dynptr *ptr, record_type_t record_type);