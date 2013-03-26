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
#include <sys/types.h>
#include <sys/wait.h>

#ifndef CLEAVE_H
#define CLEAVE_H

#ifdef __cplusplus
//extern "C" {
#endif

struct cleave_handle;
struct cleave_child;

/* Fork a new cleave daemon.
 *
 * This handle must be destroyed by calling cleave_destroy(), which will cause
 * the new daemon to exit.
 */
struct cleave_handle * cleave_create();

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
 * one of these fds can be -1 in which case the fd will be duped to /dev/null
 *
 * The returned handle *must* be freed by calling cleave_wait().
 */
struct cleave_child * cleave_child(char const **argv, int fd[3]);

/* Wait for the given child process to complete and free the handle.
 *
 * This call will deadlock if any of stdin, stdout, stderr block.
 * Returns the return code of the process. cleave_child
 */
pid_t cleave_wait(struct cleave_child *child);

/* Execute a child process and block waiting for the child to complete.
 *
 * You can optionally provide callbacks to write(2) data into the child stdin,
 * and read(2) data from stdout and stderr. All file descriptors are
 * non-blocking. These callbacks will keep being called so long as they
 * return zero (success).
 *
 * Returns -1 with errno set appropriately on an error, otherwise returns the
 * child process exit code.
 */
pid_t cleave_popen(char const **argv,
		   int (*write_stdin)(int fd),
		   int (*read_stdout)(int fd),
		   int (*read_stderr)(int fd),
		   void *priv);

#ifdef __cplusplus
}
#endif



#endif
