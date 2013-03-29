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
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <cleave.h>
#include "syscall.h"

struct cleave_handle {
	pid_t child_pid;
	int sock;
};

struct cleave_child {
	int wait_pipe;
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

static char to_hex(unsigned char v)
{
	static char result[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	assert(v < sizeof(result));
	return result[v];
}

static int urlencode(char const *str, char *ret)
{
	char *pret = ret;
	const char *pstr;

	for (pstr = str; *pstr; ++pstr) {
		if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
			*pret++ = *pstr;
		else if (*pstr == ' ')
			*pret++ = '+';
		else
			*pret++ = '%', *pret++ = to_hex(*pstr >> 4), *pret++ = to_hex(*pstr & 15);
		pret++;
	}
	*pret = '\0';
	return pret - ret;
}

static int urlencode_len(int length)
{
	return (length * 3 + 1);
}

/* Encode argv as a string of the form:
 *  exec=urlencode(argv[0]),urlencode(argv[1]),urlencode(argv[2])\n
 */
static char *encodeargs(char const **argv)
{
	char const **arg;
	char *buf = NULL, *p = NULL;
	int len;

	len = 7;
	for (arg = argv; *arg; ++arg)
		len += 1 + urlencode_len(strlen(*arg));
	buf = malloc(len);
	if (!buf) {
		errno = ENOMEM;
		return NULL;
	}

	strcpy(buf, "exec=");
	p = buf + strlen(buf);
	for (arg = argv; *arg; ++arg) {
		p += urlencode(*arg, p);
		if (arg[1]) {
			*p++ = ',';
		}
	}
	*p++ = '\n';
	*p++ = '\0';

	return buf;
}

struct cleave_handle * cleave_create(int error_fd)
{
	int err_pipe[2], sock[2], nullfd, fd, ret, last_errno;
	struct cleave_handle *handle;
	char child_port[10], buf[10];
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

		if (do_close(err_pipe[0]) == -1 ||
		    do_close(sock[0]) == -1 ||
		    do_setfd(sock[1], 0, FD_CLOEXEC) == -1)
			goto child_error;

		/* divorce child */
		nullfd = open("/dev/null", O_RDWR);
		if (nullfd == -1)
			goto child_error;
		if (dup2(nullfd, 0) == -1 ||
		    dup2(nullfd, 1) == -1 ||
		    dup2(error_fd != -1 ? error_fd : nullfd, 2) == -1 ||
		    do_close(nullfd))
			goto child_error;

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
	sock[1] = -1;

	/* check if the child forked properly */
	ret = do_read(err_pipe[0], buf, sizeof(buf));
	if (ret) {
		errno = atoi(buf);
		do_close(err_pipe[0]);
		do_close(sock[0]);
		free(handle);
		return NULL;
	}
	do_close(err_pipe[0]);

	handle->child_pid = pid;
	handle->sock = sock[0];

	return handle;

exit_pipe:
	last_errno = errno;
	do_close(sock[0]);
	do_close(sock[1]);
	errno = last_errno;
exit_close:
	free(handle);

	return NULL;
}

struct cleave_handle * cleave_attach(char const *path)
{
	struct cleave_handle *handle;
	struct sockaddr_un remote;
	int sock, len, last_errno;

	if (strlen(path) >= sizeof(remote.sun_path)) {
		errno = EINVAL;
		return NULL;
	}

	handle = malloc(sizeof(struct cleave_handle));
	if (!handle) {
		errno = ENOMEM;
		return NULL;
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1)
		goto exit_socket;

	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, path);
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(sock, (struct sockaddr *)&remote, len) == -1)
		goto exit_connect;

	handle->sock = sock;
	handle->child_pid = 0;
	return handle;

exit_connect:
	last_errno = errno;
	do_close(sock);
	errno = last_errno;
exit_socket:
	free(handle);

	return NULL;
}

void cleave_destroy(struct cleave_handle *handle)
{
	do_close(handle->sock);

	if (handle->child_pid) {
		int status;
		do_waitpid(handle->child_pid, &status, 0);
	}

	free(handle);
}

struct cleave_child *cleave_child(struct cleave_handle *handle, char const **argv, int in_fd[3])
{
	int fd[4], exit_pipe[2], nullfd = -1, i, ret;
	struct cleave_child * child;
	char *encoded_args;
	struct iovec data;
	struct msghdr hdr;
	char cmsgbuf[CMSG_SPACE(sizeof(fd))];
	struct cmsghdr *cmsg;

	child = malloc(sizeof(*child));
	if (!child) {
		errno = ENOMEM;
		return NULL;
	}

	encoded_args = encodeargs(argv);
	if (!encoded_args) {
		errno = ENOMEM;
		goto exit_encode;
	}

	/* We use a pipe to wait for the process to terminate */
	if (pipe2(exit_pipe, O_CLOEXEC) == -1)
		goto exit_pipe;

	/* We can't pass invalid file descriptors over the socket,
	 * so pass fds to null instead */
	memcpy(fd, in_fd, sizeof(in_fd));
	if (in_fd[0] == -1 || in_fd[1] == -1 || in_fd[2] == -1) {
		nullfd = open("/dev/null", O_RDWR);
		if (nullfd == -1)
			goto exit_nullfd;
		for (i = 0; i < 3; i++) {
			if (fd[i] == -1)
				fd[i] = nullfd;
		}
	}
	fd[3] = exit_pipe[1];

	data.iov_base = encoded_args;
	data.iov_len = strlen(encoded_args) + 1;

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_name = NULL;
	hdr.msg_namelen = 0;
	hdr.msg_iov = &data;
	hdr.msg_iovlen = 1;
	hdr.msg_flags = 0;

	hdr.msg_control = cmsgbuf;
	hdr.msg_controllen = CMSG_LEN(sizeof(fd));

	cmsg = CMSG_FIRSTHDR(&hdr);
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(cmsg), fd, sizeof(fd));

	ret = sendmsg(handle->sock, &hdr, 0);
	if (ret == -1)
		goto exit_sendmsg;

	if (nullfd != -1)
		do_close(nullfd);
	do_close(exit_pipe[1]);
	free(encoded_args);

	child->wait_pipe = exit_pipe[0];
	return child;

exit_sendmsg:
	if (nullfd != -1)
		close(nullfd);
exit_nullfd:
	do_close(exit_pipe[0]);
	do_close(exit_pipe[1]);
exit_pipe:
	free(encoded_args);
exit_encode:
	free(child);

	return NULL;
}

int cleave_wait_fd(struct cleave_child *child)
{
	return dup(child->wait_pipe);
}

pid_t cleave_wait(struct cleave_child *child)
{
	char buf[16], *p = buf;
	int len, ret;

	/* Just block waiting for output from cleave_child */
	for (;;) {
		len = buf + sizeof(buf) - p - 1;
		if (len == 0) {
			errno = EINVAL;
			ret = -1;
			break;
		}
		ret = do_read(child->wait_pipe, p, len);
		if (ret == -1)
			break;
		else if (ret == 0) {
			if (buf != p) {
				*p = '\0';
				ret = atoi(buf);
			} else {
				errno = EINVAL;
				ret = -1;
			}
		} else {
			p += ret;
		}
	}

	do_close(child->wait_pipe);
	free(child);

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
