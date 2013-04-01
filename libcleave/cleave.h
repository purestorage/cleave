/*
 * libcleave: fork/exec daemon client library
 *
 * The cleaved source code is licensed to you under a BSD 2-Clause
 * license, included below.
 *
 * Copyright © 2013 Pure Storage, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef CLEAVE_H
#define CLEAVE_H

#ifdef __cplusplus
//extern "C" {
#endif

struct cleave_handle;
struct cleave_child;

/* Provide a callback for cleave logging */
void cleave_set_logfn(void (*log)(char const *format, va_list args));

/* Fork a new cleave daemon.
 *
 * This handle must be destroyed by calling cleave_destroy(), which will cause
 * the new daemon to exit.
 *
 * The passed error_fd is connected to stderr of the child process. Specify
 * -1 if you don't want to see any errors.
 */
struct cleave_handle * cleave_create(int error_fd);

/* Attach to a running cleave daemon at the given socket
 *
 * This handle must be destroyed by calling cleave_destroy(). The ademon will
 * continue to run after cleave_destroy().
 */
struct cleave_handle * cleave_attach(char const *socket);

/* Detach from the running cleave daemon. */
void cleave_destroy(struct cleave_handle *handle);

/* Execute a child process
 *
 * The fd array is an array of three pipe fd's - stdin, stdout, stderr. Any
 * one of these fds can be -1 in which case the fd will be duped to /dev/null.
 *
 * The returned handle *must* be freed by calling cleave_wait().
 */
struct cleave_child * cleave_child(struct cleave_handle *handle,
				   char const **argv, int fd[3]);

/* Wait for the given child process to complete and free the handle.
 *
 * This call will deadlock if any of stdin, stdout, stderr fill and
 * aren't drained by the client.
 *
 * Returns the return code of the process, or -1.
 * The cleave_child is always invalid after this call, even if -1 is returned.
 */
pid_t cleave_wait(struct cleave_child *child);

/* Return a *new* file descriptor that can be used in select/poll/epoll to
 * determine when to call cleave_wait(). It is the callers responsibility to
 * close this file descriptor once cleave_wait returns. Do *not* read/write
 * to this file descriptor.
 */
int cleave_wait_fd(struct cleave_child *child);

/* Return the pid of the child */
pid_t cleave_pid(struct cleave_child *child);

/* Execute a child process and block waiting for the child to complete.
 *
 * Each of stdin, stdout, stderr can be dup2'd to an existing file descriptor
 * (in which case it is the callers responsibility to ensure we don't deadlock),
 * or a callback parameterised by the file descriptor.
 *
 * rw: Provide a callback to read/write to the file descriptor. Keep reading
 *	writing until there's more data to write, or until read() returns zero.
 *	Return non-zero to close the file descriptor [do not under any
 *	circumstances call fclose() yourself].
 * iovec: Provide a single buffer for stdin and a single buffer for stdout/stderr.
 *	When the process has complete iov_len will be set to the number of bytes
 *	actually transferred.
 */
struct cleave_exec_param {
	int dup2_fd;
	int (*rw)(int fd, void *priv);
	struct iovec iov;
};

pid_t cleave_exec(struct cleave_handle *handle,
		  char const **argv, struct cleave_exec_param param[3],
		  void *priv);

#ifdef __cplusplus
}
#endif

#endif
