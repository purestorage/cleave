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
#include <stdbool.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <cleave.h>
#include "syscall.h"

/**
 * @child_pid: The pid of the cleaved process we started, or -1 if attached.
 * @sock: The socket used to talk to cleaved.
 */
struct cleave_handle {
	pid_t child_pid;
	int sock;
};

/**
 * @buf: fields returned by cleaved
 * @buflen: length of %buf
 * @wait_pipe: Pipe used to return %buf
 */
struct cleave_child {
	char *buf;
	ssize_t buflen;
	int wait_pipe;
};

static char * const daemon_path = "cleaved";

static void cleave_log_null(char const *format __attribute__((unused)),
			    va_list args __attribute__((unused))) { }
static void (*cleave_logfn)(char const *format, va_list args) = cleave_log_null;

static void __attribute__((format (printf, 1, 2)))
cleave_log(char const *format, ...)
{
	va_list args;

	va_start(args, format);
	cleave_logfn(format, args);
	va_end(args);
}

static void
cleave_perror(const char *s)
{
	cleave_log("%s: %s\n", s, strerror(errno));
}

static int do_setfd(int sock, int add_flags, int del_flags)
{
	 int flags, s;

	 flags = fcntl(sock, F_GETFD, 0);
	 if (flags == -1) {
		 cleave_perror("fcntl");
		 return -1;
	 }
	 flags = (flags | add_flags) & ~del_flags;
	 s = fcntl(sock, F_SETFD, flags);
	 if (s == -1) {
		 cleave_perror("fcntl");
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
		else {
			*pret++ = '%';
			*pret++ = to_hex(*pstr >> 4);
			*pret++ = to_hex(*pstr & 15);
		}
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
		cleave_perror("malloc");
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

void cleave_set_logfn(void (*logfn)(char const *format, va_list args))
{
	cleave_logfn = logfn;
}

struct cleave_handle * cleave_create(int error_fd)
{
	int err_pipe[2], sock[2], nullfd, fd, ret, last_errno;
	struct cleave_handle *handle;
	char child_port[10];
	pid_t pid;

	handle = malloc(sizeof(struct cleave_handle));
	if (!handle) {
		errno = ENOMEM;
		cleave_perror("malloc");
		return NULL;
	}

	/* all sockets/pipes are CLOEXEC in the parent */
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sock) == -1) {
		cleave_perror("socketpair");
		free(handle);
		return NULL;
	}
	snprintf(child_port, sizeof(child_port), "%d", sock[1]);

	if (pipe2(err_pipe, O_CLOEXEC) == -1) {
		cleave_perror("pipe2");
		if (do_close(sock[0]) || do_close(sock[1]))
			cleave_perror("close");
		free(handle);
		return NULL;
	}

	pid = fork();
	if (!pid) {
		/* child */
		struct rlimit rlim;

		if (do_close(err_pipe[0]) == -1 ||
		    do_close(sock[0]) == -1) {
			cleave_perror("close");
			goto child_error;
		}
		if (do_setfd(sock[1], 0, FD_CLOEXEC) == -1)
			goto child_error;

		/* divorce child */
		nullfd = open("/dev/null", O_RDWR);
		if (nullfd == -1) {
			cleave_perror("open");
			goto child_error;
		}
		if (dup2(nullfd, 0) == -1 ||
		    dup2(nullfd, 1) == -1 ||
		    dup2(error_fd != -1 ? error_fd : nullfd, 2) == -1) {
			cleave_perror("dup2");
			goto child_error;
		}
		if (do_close(nullfd) == -1) {
			cleave_perror("close");
			goto child_error;
		}

		/* close all open fds */
		if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
			cleave_perror("getrlimit");
			goto child_error;
		}
		for (fd = 3; fd < (int)rlim.rlim_cur; ++fd) {
			if (fd != sock[1] && fd != err_pipe[1])
				do_close(fd);
		}

		/* geronimo */
		execlp(daemon_path, daemon_path, "-n", child_port, NULL);
		cleave_perror("execlp");
	child_error:
		last_errno = errno;
		do_write(err_pipe[1], &last_errno, sizeof(last_errno));
		_exit(127);
	}

	/* parent */
	if (do_close(err_pipe[1]) || do_close(sock[1]))
		cleave_perror("close");
	sock[1] = -1;

	/* check if the child forked properly */
	ret = do_read(err_pipe[0], &last_errno, sizeof(last_errno));
	if (ret) {
		if (do_close(err_pipe[0]) || do_close(sock[0]))
			cleave_perror("close");
		free(handle);
		if (ret == sizeof(last_errno))
			errno = last_errno;
		return NULL;
	}
	if (do_close(err_pipe[0]))
		cleave_perror("close");

	handle->child_pid = pid;
	handle->sock = sock[0];

	return handle;
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
		cleave_perror("malloc");
		return NULL;
	}

	sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock == -1) {
		cleave_perror("socket");
		goto exit_socket;
	}

	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, path);
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(sock, (struct sockaddr *)&remote, len) == -1) {
		cleave_perror("connect");
		goto exit_connect;
	}

	handle->sock = sock;
	handle->child_pid = 0;
	return handle;

exit_connect:
	last_errno = errno;
	if (do_close(sock))
		cleave_perror("close");
	errno = last_errno;
exit_socket:
	free(handle);

	return NULL;
}

void cleave_destroy(struct cleave_handle *handle)
{
	if (do_close(handle->sock))
		cleave_perror("close");

	if (handle->child_pid) {
		int status;
		if (do_waitpid(handle->child_pid, &status, 0) == -1)
			cleave_perror("waitpid");
	}

	free(handle);
}

/* Read more data from the (blocking) child exit_pipe */
static int child_readmsg(struct cleave_child *child)
{
	char *newbuf, buf[64];
	int ret;

	ret = do_read(child->wait_pipe, buf, sizeof(buf));
	if (ret < 0) {
		cleave_perror("read");
		return -1;
	} else if (ret == 0) {
		cleave_log("unexpected end of wait_pipe");
		return -1;
	}

	newbuf = realloc(child->buf, child->buflen + ret);
	if (!newbuf) {
		errno = ENOMEM;
		cleave_perror("malloc");
		return -1;
	}
	memcpy(newbuf + child->buflen, buf, ret);
	child->buf = newbuf;
	child->buflen += ret;
	return 0;
}

/* Search for the given field in the child msg buffer. Returns true if
 * the field was present */
static bool child_getfield(struct cleave_child *child, char *field, int *value)
{
	int i, fieldlen, sol;

	if (!child->buf)
		return false;

	fieldlen = strlen(field);
	sol = 0;
	for (i = 0; i < child->buflen; i++) {
		if (child->buf[i] == '\n') {
			if (i - sol >= fieldlen + 2) {
				if (!strncmp(child->buf + sol, field, fieldlen) &&
				    child->buf[sol + fieldlen] == '=') {
					*value = atoi(child->buf + sol + fieldlen + 1);
					return true;
				}
			}
			sol = i + 1;
		}
	}

	return false;
}

struct cleave_child *cleave_child(struct cleave_handle *handle, char const **argv, int in_fd[3])
{
	int fd[4], exit_pipe[2], nullfd = -1, i, ret, child_errno = 0;
	struct cleave_child *child;
	char *encoded_args;
	struct iovec data;
	struct msghdr hdr;
	char cmsgbuf[CMSG_SPACE(sizeof(fd))];
	struct cmsghdr *cmsg;

	child = malloc(sizeof(*child));
	if (!child) {
		errno = ENOMEM;
		cleave_perror("malloc");
		return NULL;
	}
	memset(child, 0, sizeof(*child));

	encoded_args = encodeargs(argv);
	if (!encoded_args) {
		errno = ENOMEM;
		goto exit_encode;
	}

	/* We use a blocking pipe to send pid/rc back from cleaved */
	if (pipe2(exit_pipe, O_CLOEXEC) == -1) {
		cleave_perror("pipe2");
		goto exit_pipe;
	}

	/* We can't pass invalid file descriptors over the socket,
	 * so pass fds to null instead */
	memcpy(fd, in_fd, sizeof(int) * 3);
	if (fd[0] == -1 || fd[1] == -1 || fd[2] == -1) {
		nullfd = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (nullfd == -1) {
			cleave_perror("open");
			goto exit_nullfd;
		}
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

	memset(cmsgbuf, 0, sizeof(cmsgbuf));
	cmsg = CMSG_FIRSTHDR(&hdr);
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(cmsg), fd, sizeof(fd));

	ret = sendmsg(handle->sock, &hdr, 0);
	if (ret == -1) {
		cleave_perror("sendmsg");
		goto exit_sendmsg;
	}

	if (do_close(exit_pipe[1]))
		cleave_perror("close");
	exit_pipe[1] = -1;
	child->wait_pipe = exit_pipe[0];

	/* Block until we receive pid= or errno= so we can return a good error code.
	 * This also allows the client to use select/poll/epoll via cleave_wait_fd(),
	 * without getting confused by additional fields. */
	while (true) {
		if (child_getfield(child, "errno", &child_errno))
			goto exit_last;
		if (child_getfield(child, "pid", &i))
			break;
		if (child_readmsg(child) == -1)
			goto exit_last;
	}

	if (nullfd != -1) {
		if (do_close(nullfd))
			cleave_perror("close");
	}
	free(encoded_args);

	return child;

exit_last:
exit_sendmsg:
	if (nullfd != -1)
		close(nullfd);
exit_nullfd:
	for (i = 0; i < 2; i++) {
		if (exit_pipe[i] != -1) {
			if (do_close(exit_pipe[i]))
				cleave_perror("close");
		}
	}
exit_pipe:
	free(encoded_args);
exit_encode:
	free(child);
	if (child_errno)
		errno = child_errno;
	return NULL;
}

int cleave_wait_fd(struct cleave_child *child)
{
	return child->wait_pipe;
}

int cleave_pid(struct cleave_child *child)
{
	int pid;

	while (true) {
		if (child_getfield(child, "pid", &pid))
			return pid;
		if (child_readmsg(child) == -1)
			return -1;
	}
}

pid_t cleave_wait(struct cleave_child *child)
{
	pid_t ret;

	while (true) {
		if (child_getfield(child, "rc", &ret))
			break;
		if (child_readmsg(child) == -1)
			return -1;
	}
	if (do_close(child->wait_pipe))
		cleave_perror("close");
	if (child->buf)
		free(child->buf);
	free(child);

	return ret;
}

pid_t cleave_exec(struct cleave_handle *handle,
		  char const **argv, struct cleave_exec_param param[3],
		  void *priv)
{
	int child_fd[3] = {-1, -1, -1}, parent_fd[3] = {-1, -1, -1};
	int i, epollfd = -1, open_fds = 0, ret, last_errno;
	size_t offset[3] = {0, 0, 0};
	struct epoll_event ev;
	struct cleave_child *child = NULL;
	bool close_fd;
	pid_t pid = -1;

	/* Verify input parameters */
	for (i = 0; i < 3; i++) {
		if ((param[i].dup2_fd != -1) + !!param[i].iov.iov_base + !!param[i].rw > 1) {
			cleave_log("invalid parameters");
			errno = EINVAL;
			goto fail;
		}
	}

	/* Setup the child_fd[] array for cleave_child() creating any
	 * needed pipes */
	for (i = 0; i < 3; i++) {
		if (param[i].dup2_fd != -1)
			child_fd[i] = param[i].dup2_fd;
		else if (param[i].rw || param[i].iov.iov_base) {
			int pipe_fd[2];
			if (pipe2(pipe_fd, O_CLOEXEC | O_NONBLOCK) == -1) {
				cleave_perror("pipe2");
				goto fail;
			}
			child_fd[i] = pipe_fd[i == 0 ? 0 : 1];
			parent_fd[i] = pipe_fd[i == 0 ? 1 : 0];
		}
	}

	/* Start the child then close our end of the pipes */
	if ((child = cleave_child(handle, argv, child_fd)) == NULL)
		goto fail;
	for (i = 0; i < 3; i++) {
		if (param[i].rw || param[i].iov.iov_base) {
			if (do_close(child_fd[i]))
				cleave_perror("close");
			child_fd[i] = -1;
		}
	}

	/* Setup epoll */
	epollfd = epoll_create(1);
	if (epollfd < 0) {
		cleave_perror("epoll");
		goto fail;
	}
	for (i = 0; i < 3; i++) {
		if (param[i].rw || param[i].iov.iov_base) {
			ev.events = EPOLLIN | EPOLLOUT;
			ev.data.fd = parent_fd[i];
			if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ev.data.fd, &ev) == -1) {
				cleave_perror("epollctl");
				goto fail;
			}
			++open_fds;
		}
	}

	ev.events = 0;
	ev.data.fd = child->wait_pipe;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ev.data.fd, &ev) == -1) {
		cleave_perror("epoll_ctl");
		goto fail;
	}
	++open_fds;

	/* epoll loop */
	while (open_fds) {
		ret = epoll_wait(epollfd, &ev, 1, -1);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			cleave_perror("epoll_wait");
			goto fail;
		}
		if (ret == 0)
			continue;

		close_fd = false;
		for (i = 0; i < 3; i++) {
			if (parent_fd[i] != ev.data.fd)
				continue;
			if (ev.events & (EPOLLIN | EPOLLOUT)) {
				if (param[i].rw) {
					if (param[i].rw(parent_fd[i], priv))
						close_fd = true;
				} else if (param[i].iov.iov_base) {
					char *buf = param[i].iov.iov_base + offset[i];
					int bytes = param[i].iov.iov_len - offset[i];
					assert(bytes > 0);
					if (i == 0)
						ret = write(parent_fd[i], buf, bytes);
					else
						ret = read(parent_fd[i], buf, bytes);
					if (ret == -1) {
						if (errno != EINTR && errno != EAGAIN &&
						    errno != EWOULDBLOCK)
							close_fd = true;
					} else {
						offset[i] += ret;
						/* close the fd if the buffer
						 * is exhausted */
						close_fd = (param[i].iov.iov_len == offset[i]);
					}
				}
			}
			if (ev.events & (EPOLLHUP | EPOLLERR))
				close_fd = true;
			if (close_fd) {
				/* populate the output data length */
				if (param[i].iov.iov_base)
					param[i].iov.iov_len = offset[i];
				if (do_close(parent_fd[i]))
					cleave_perror("close");
				parent_fd[i] = -1;
				--open_fds;
			}
		}
		if (ev.data.fd == child->wait_pipe) {
			/* This will close the file descriptor */
			pid = cleave_wait(child);
			--open_fds;
		}
	}

	if (do_close(epollfd))
		cleave_perror("close");

	return pid;

fail:
	last_errno = errno;
	for (i = 0; i < 3; i++) {
		if (parent_fd[i] != -1) {
			if (do_close(parent_fd[i]))
				cleave_perror("close");
		}
		if (child_fd[i] != -1) {
			if (do_close(child_fd[i]))
				cleave_perror("close");
		}
	}
	if (epollfd != -1) {
		if (do_close(epollfd))
			cleave_perror("close");
	}
	errno = last_errno;
	return -1;
}
