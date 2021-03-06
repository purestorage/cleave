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
extern "C" {
#endif

struct cleave_handle;
struct cleave_child;

/* Provide a callback for cleave logging */
void cleave_set_logfn(void (*log)(char const *str));

/* Fork a new cleave daemon.
 *
 * This handle must be destroyed by calling cleave_destroy(), which will cause
 * the new daemon to exit.
 *
 * The passed error_fd is connected to stderr of the child process. Specify
 * -1 if you don't want to see any errors.
 *
 * By default we expect "cleave" to be in PATH. If "cleave" is installed
 * outside of PATH, or installed with a different name, then you can override
 * this behaviour by setting CLEAVE_CLEAVED_FILENAME environment variable
 */
struct cleave_handle * cleave_create(int error_fd);

/* Attach to a running cleave daemon at the given socket
 *
 * This handle must be destroyed by calling cleave_destroy(). The daemon will
 * continue to run after cleave_destroy().
 */
struct cleave_handle * cleave_attach(char const *socket);

/* Return the communication socket used to connect with the daemon.
 *
 * This is useful if you want to use poll/epoll with POLLRDHUP to check
 * when the process dies
 */
int cleave_connect_fd(struct cleave_handle *);

/* Detach from the running cleave daemon.
 *
 * If the process was started by cleave_create() then it will die when the connection
 * drops. Returns the return code from cleaved.
 */
int cleave_destroy(struct cleave_handle *handle);

/* Execute a child process
 *
 * The fd array is an array of three pipe fd's - stdin, stdout, stderr. Any
 * one of these fds can be -1 in which case the fd will be duped to /dev/null.
 *
 * This function is thread-safe. cleave_child() can be called concurrently
 * on the same cleave_handle. This function will block if the socket buffer
 * to cleaved fills, which realistically is only possible if you're executing
 * a very large command line or cleaved is somehow broken.
 *
 * The returned handle *must* be freed by calling cleave_wait().
 *
 * NB: There is currently no way to pass environment variables to the child.
 */
struct cleave_child * cleave_child(struct cleave_handle *handle,
				   char const **argv, int fd[3]);

/* Wait for the given child process to complete and free the handle.
 *
 * This call will deadlock if any of stdin, stdout, stderr fill and
 * aren't drained by the client.
 *
 * Since cleave_wait() frees the cleave_child structure, this function
 * can only be called once.
 *
 * Returns the return code of the process, or -1.
 * The cleave_child is always invalid after this call, even if -1 is returned.
 */
int cleave_wait(struct cleave_child *child);

/* Return the file descriptor that cleave_wait() uses to determine when the
 * child processes has exited. This file descriptor is one end of a pipe,
 * and the pipe is written and closed when the process completes.
 *
 * Use cleave_wait_fd() if you want to call cleave_wait() without blocking.
 * Use select/poll/epoll to wait for on this fd, then call cleave_wait().
 * Note that if you're using epoll then use EPOLLHUP to absolutely guarantee
 * to avoid blocking.
 */
int cleave_wait_fd(struct cleave_child *child);

/* Return the pid of the child */
pid_t cleave_pid(struct cleave_child *child);

#ifdef __cplusplus
}
#endif

#endif
