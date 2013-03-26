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
#include <cleave.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>

struct cleave_handle {
	pid_t child_pid;
	int sock;
};

static char * const daemon_path = "cleaved";

static int do_setfd(int sock, int add_flags, int del_flags)
{
	 int flags, s;

	 flags = fcntl(sock, F_GETFD, 0);
	 if (flags == -1) {
		 return -1;
	 }
	 flags = (flags | add_flags) & ~del_flags;
	 s = fcntl(sock, F_SETFD, flags);
	 if (s == -1) {
		 return -1;
	 }

	 return 0;
}

static int do_close(int sock)
{
	int ret;
again:
	ret = close(sock);
	if (ret == -1 && errno == EINTR)
		goto again;
	return ret;
}

static int do_write(int fd, const void * buf, size_t size)
{
	size_t pos;
	int ret;

	for (pos = 0; pos < size; ++pos) {
		ret = write(fd, buf + pos, size - pos);
		if (ret == -1 && errno != EINTR)
			return -1;
		else if (ret >= 0)
			pos += ret;
	}

	return size;
}

static int do_read(int fd, void *buf, size_t size)
{
	int ret;

again:
	ret = read(fd, buf, size);
	if (ret == -1 && errno == EINTR)
		goto again;
	return ret;
}

static int do_waitpid(pid_t pid, int *status)
{
	int ret;

again:
	ret = waitpid(pid, status, 0);
	if (ret == -1 && errno == EINTR)
		goto again;
	return ret;
}

struct cleave_handle * cleave_create()
{
	struct cleave_handle *handle;
	char child_port[10], buf[10];
	int err_pipe[2], sock[2], nullfd, fd, ret;
	pid_t pid;

	handle = malloc(sizeof(struct cleave_handle));
	if (!handle) {
		errno = ENOMEM;
		return NULL;
	}

	/* all sockets/pipes are CLOEXEC in the parent */
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sock) == -1)
		goto exit_close;
	snprintf(child_port, sizeof(child_port), "%d", sock[1]);

	if (pipe2(err_pipe, O_CLOEXEC) == -1)
		goto exit_pipe;

	pid = fork();
	if (!pid) {
		/* child */
		struct rlimit rlim;

		if (do_close(err_pipe[0]) == -1)
			goto child_error;
		if (do_close(sock[0]) == -1)
			goto child_error;
		if (do_setfd(sock[1], 0, FD_CLOEXEC) == -1)
			goto child_error;

		/* divorce child */
		nullfd = open("/dev/null", O_RDWR);
		if (nullfd == -1)
			goto child_error;
		dup2(nullfd, 0);
		dup2(nullfd, 1);
		dup2(nullfd, 2);

		/* close all open fds */
		if (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
			goto child_error;
		for (fd = 3; fd < (int)rlim.rlim_cur; ++fd) {
			if (fd != sock[1] && fd != err_pipe[1])
				do_close(fd);
		}

		/* geronimo */
		execlp(daemon_path, daemon_path, "-n", child_port, NULL);

	child_error:
		ret = snprintf(buf, sizeof(buf), "%d", errno);
		do_write(err_pipe[1], buf, ret);
		_exit(127);
	}

	/* parent */
	do_close(err_pipe[1]);
	do_close(sock[1]);

	/* check if the child forked properly */
	ret = do_read(err_pipe[0], buf, sizeof(buf));
	if (ret) {
		errno = atoi(buf);
		goto exit_nochild;
	}
	do_close(err_pipe[0]);

	handle->child_pid = pid;
	handle->sock = sock[0];

	return handle;

exit_nochild:
	do_close(err_pipe[0]);
	do_close(sock[0]);
exit_pipe:
	do_close(sock[0]);
	do_close(sock[1]);
exit_close:
	free(handle);

	return NULL;
}

struct cleave_handle * cleave_attach(char const *socket __attribute__((unused)))
{
	return NULL;
}

void cleave_destroy(struct cleave_handle *handle)
{
	do_close(handle->sock);

	if (handle->child_pid) {
		int status;
		do_waitpid(handle->child_pid, &status);
	}

	free(handle);
}

struct cleave_child * cleave_child(char const **argv __attribute__((unused)), int fd[3] __attribute__((unused)))
{
	return NULL;
}

pid_t cleave_wait(struct cleave_child *child __attribute__((unused)))
{
	return 0;
}

pid_t cleave_popen(char const **argv __attribute__((unused)),
		   int (*write_stdin)(int fd) __attribute__((unused)),
		   int (*read_stdout)(int fd) __attribute__((unused)),
		   int (*read_stderr)(int fd) __attribute__((unused)),
		   void *priv __attribute__((unused)))
{
	return 0;
}
