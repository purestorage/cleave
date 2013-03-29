/*
 * cleaved: fork/exec daemon
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

/**
 * TODO
 * signalfd for SIGHUP and SIGCHILD, process notification
 * better logging
 * SA_RESTART
 *...
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

struct child_proc {
	struct child_proc *next;
	char **argv;
	int fd[3];
	int exit_pipe;
	pid_t pid;
};

static char *readbuf;
static size_t readbuf_len;

#define verb(...) fprintf(stderr, __VA_ARGS__)

static void  __attribute__((noreturn)) out_of_memory()
{
	verb("out of memory");
	abort();
}

static int epoll_op(int epollfd, int op, int flags, int fd)
{
	struct epoll_event ev;

	ev.events = flags;
	ev.data.fd = fd;
	if (epoll_ctl(epollfd, op, fd, &ev) == -1) {
		perror("epoll_ctl");
		return -1;
	}

	return 0;
}

static int do_fcntl(int sock, int get, int set, int add_flags, int del_flags)
{
	 int flags, s;

	 flags = fcntl(sock, get, 0);
	 if (flags == -1) {
		 perror("fcntl");
		 return -1;
	 }
	 flags = (flags | add_flags) & ~del_flags;
	 s = fcntl(sock, set, flags);
	 if (s == -1) {
		 perror("fcntl");
		 return -1;
	 }

	 return 0;
}

static int setup_listen_socket(char *path)
{
	int sock;
	struct sockaddr_un local;
	int len;

	sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (sock == -1) {
		perror("socket");
		return -1;
	}
	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, path);
	unlink(path); // ignore error
	len = strlen(local.sun_path) + sizeof(local.sun_family);
	if (bind(sock, (struct sockaddr *)&local, len) == -1) {
		perror("bind");
		return -1;
	}
	if (listen(sock, 5) == -1) {
		perror("listen");
		return -1;
	}

	return sock;
}

static int accept_listen_socket(int socket, int epollfd)
{
	while (1) {
		struct sockaddr in_addr;
		socklen_t in_len;
		int in_fd;

		in_len = sizeof(in_addr);
		in_fd = accept(socket, &in_addr, &in_len);
		if (in_fd == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			perror("accept");
			return -1;
		}

		if (do_fcntl(in_fd, F_GETFD, F_SETFD, O_CLOEXEC, 0) ||
		    do_fcntl(in_fd, F_GETFL, F_SETFL, O_NONBLOCK, 0) ||
		    epoll_op(epollfd, EPOLL_CTL_ADD, EPOLLIN, in_fd)) {
			close(in_fd);
			return -1;
		}
		verb("socket %d: connected\n", in_fd);
	}

	return 0;
}

static char from_hex(unsigned char v)
{
	if (v >= 'A' && v <= 'F')
		return 10 + (v - 'A');
	else if (v >= '0' && v <= '9')
		return 0 + (v - '0');
	else
		return 0;
}

static int urldecode(char const *str, char *ret)
{
	char const *pstr = str;
	char *pret = ret;

	while (*pstr) {
		if (*pstr == '%') {
			if (pstr[1] && pstr[2]) {
				*pret++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
				pstr += 2;
			}
		} else if (*pstr == '+') {
			*pret++ = ' ';
		} else {
			*pret++ = *pstr;
		}
		pstr++;
	}
	*pret = '\0';
	return pret - ret;
}

/* Message consists of
 *   exec=urlencode(argv[0]),urlencode(argv[1]),urlencode(argv[2])\n
 */
static int decode_message(struct child_proc *child, char *buf)
{
	int argcount, size;
	char **argv, *pbuf, *argbuf;

	if (strncmp(buf, "exec=", 5)) {
		verb("unknown message type\n");
		return -1;
	}
	buf += 5;

	/* Count the number of arguments in first line */
	for (pbuf = buf, argcount = 0; *pbuf; pbuf++) {
		if (*pbuf == ',')
			++argcount;
		else if (*pbuf == '\n') {
			++argcount;
			break;
		}
	}
	size = pbuf - buf;

	argv = malloc(sizeof(char *) * (argcount + 1));
	if (!argv)
		out_of_memory();

	/* Allocate a single buffer for all of the decoded strings, which
	 * is guaranteed to be less than the number of bytes above */
	argbuf = malloc(size);
	if (!argbuf)
		out_of_memory();

	/* Start decoding the mesage */
	for (pbuf = buf, argcount = 0; *pbuf; pbuf++) {
		if (*pbuf == ',' || *pbuf == '\n') {
			*pbuf = '\0';
			argv[argcount++] = argbuf;
			/* Include the NUL between each decoded argument */
			argbuf += urldecode(buf, argbuf) + 1;
			buf = pbuf + 1;
		}
	}
	argv[argcount] = NULL;

	child->argv = argv;
	return 0;
}

/* Read the incoming message into read_buf [preallocated to the maximum
 * size], and the associated file descriptors. There are four file descriptors,
 * fd[0..3] which we'll connect directly to the child, and fd[3] which we'll
 * use to communicate the exit code back to the client.
 */
static struct child_proc *read_incoming_message(int sock)
{
	struct child_proc *child;
	int fd[4], ret;
	size_t nfd = 0, i;
	char cmsgbuf[CMSG_SPACE(sizeof(fd))];
	struct iovec data;
	struct msghdr hdr;
	struct cmsghdr *cmsg;

	child = malloc(sizeof(struct child_proc));
	if (!child)
		out_of_memory();
	memset(child, 0, sizeof(*child));

	data.iov_base = readbuf;
	data.iov_len = readbuf_len;

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = &data;
	hdr.msg_iovlen = 1;
	hdr.msg_name = NULL;
	hdr.msg_namelen = 0;
	hdr.msg_flags = 0;

	hdr.msg_control = cmsgbuf;
	hdr.msg_controllen = CMSG_LEN(sizeof(fd));

	ret = recvmsg(sock, &hdr, MSG_CMSG_CLOEXEC);
	if (ret == -1) {
		perror("recvmsg");
		goto exit_recvmsg;
	}

	if (hdr.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) {
		verb("recvmsg truncated\n");
		goto exit_recvmsg;
	}

	cmsg = CMSG_FIRSTHDR(&hdr);
	nfd = (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(fd[0]);
	if (nfd != 4) {
		verb("incorrect number of file descriptors %d\n", (int)nfd);
		goto exit_recvmsg;
	}

	if (decode_message(child, readbuf) == -1)
		goto exit_recvmsg;

	memcpy(fd, CMSG_DATA(cmsg), sizeof(fd));
	memcpy(child->fd, fd, sizeof(child->fd));
	child->exit_pipe = fd[3];

	/* If the client gave us more file descriptors, close them */
	cmsg = CMSG_NXTHDR(&hdr, cmsg);
close_fds:
	while (cmsg != NULL) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
			nfd = (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(fd[0]);
			memcpy(fd, CMSG_DATA(cmsg), sizeof(fd));
			for (i = 0; i < nfd; i++)
				close(fd[i]);
		}
		cmsg = CMSG_NXTHDR(&hdr, cmsg);
	}
	return child;

exit_recvmsg:
	/* Close all of the file descriptors we received */
	cmsg = CMSG_FIRSTHDR(&hdr);
	free(child);
	child = NULL;
	goto close_fds;
}

/* Destroy a struct child_proc created by read_incoming_message */
static void destroy_child(struct child_proc *child)
{
	size_t i;

	assert(!child->next);
	if (child->argv) {
		free(child->argv[0]);
		free(child->argv);
	}
	for (i = 0; i < sizeof(child->fd) / sizeof(child->fd[0]); i++) {
		if (child->fd[i] != -1)
			close(child->fd[i]);
	}
	if (child->exit_pipe != -1)
		close(child->exit_pipe);
	free(child);
}

static int start_child(struct child_proc *child __attribute__((unused)))
{
	int err_pipe[2], ret;
	pid_t pid;
	char buf[10];

	if (pipe2(err_pipe, O_CLOEXEC) == -1) {
		perror("pipe2");
		return -1;
	}

	pid = fork();
	if (!pid) {
		/* child */
		if (close(err_pipe[0]) == -1)
			goto child_error;

		if (dup2(child->fd[0], 0) == -1 ||
		    dup2(child->fd[1], 1) == -1 ||
		    dup2(child->fd[2], 2) == -1)
			goto child_error;

		close(child->fd[0]);
		close(child->fd[1]);
		close(child->fd[2]);

		execvp(child->argv[0], child->argv);
	child_error:
		ret = snprintf(buf, sizeof(buf), "%d", errno);
		ret = write(err_pipe[1], buf, ret);
		_exit(127);
	}

	/* parent */
	close(err_pipe[1]);
	close(child->fd[0]);
	close(child->fd[1]);
	close(child->fd[2]);
	child->fd[0] = child->fd[1] = child->fd[2] = -1;

	/* check if the child forked properly */
	ret = read(err_pipe[0], buf, sizeof(buf));
	if (ret) {
		close(err_pipe[0]);
		errno = atoi(buf);
		return -1;
	}
	close(err_pipe[0]);
	return 0;
}


static void usage(char const *prog)
{
        printf("Usage:\n");
        printf("  %s         fork/exec daemon\n", prog);
        printf("\n");
        printf("Options:\n");
        printf("  -l, --listen=<path>     open a unix domain socket at the given path\n");
        printf("  -n, --number=<fd>       start listening on the given socket number\n");
        printf("  -h, --help              print this usage information and exit\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	static int epollfd;
	struct epoll_event ev;
	char *listen_path = NULL;
	int  socket_number = -1, listen_socket = -1, ret;
	struct child_proc *child, *children = NULL;

	while (1) {
		int c;

		static struct option long_options[] = {
			{ .name = "listen",     .has_arg = 1,   .val = 'l' },
			{ .name = "number",     .has_arg = 1,   .val = 'n' },
			{ .name = "help",       .has_arg = 0,   .val = 'h' },
		};

		c = getopt_long(argc, argv, "l:n:h", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'l':
			listen_path = strdupa(optarg);
                        break;
		case 'n':
			socket_number = atoi(optarg);
                        break;
		case 'h':
			usage(argv[0]);
			return 0;
		}
	}

	if (!listen_path && socket_number == -1) {
		usage(argv[0]);
		return 1;
	}

	/* read_incoming_message receives a message containing an array of
	 * urlencoded arguments:
	 *   arg=%5D\n
	 * The worst case size is one url encoded byte per argument
	 */
	readbuf_len = sysconf(_SC_ARG_MAX) * 8 + 20;
	readbuf = malloc(readbuf_len);
	if (!readbuf)
		out_of_memory();

	epollfd = epoll_create(1);
	if (epollfd < 0) {
		perror("epoll_create");
		return 2;
	}
	
        if (socket_number != -1) {
		if (do_fcntl(socket_number, F_GETFD, F_SETFD, FD_CLOEXEC, 0) ||
		    do_fcntl(socket_number, F_GETFL, F_SETFL, O_NONBLOCK, 0))
			return 3;
		if (epoll_op(epollfd, EPOLL_CTL_ADD, EPOLLIN, socket_number))
			return 4;
        } else if (listen_path) {
                listen_socket = setup_listen_socket(listen_path);
                if (listen_socket < 0)
                        return 5;
		if (epoll_op(epollfd, EPOLL_CTL_ADD, EPOLLIN, listen_socket))
			return 6;
	}

        /* Main event loop */

        while (1) {
                ret = epoll_wait(epollfd, &ev, 1, -1);
                if (ret < 0) {
                        if (errno == EINTR)
                                continue;
                        perror("epoll_wait");
                        return 7;
                }
                if (ret == 0)
                        continue;

                if (ev.data.fd == listen_socket) {
                        int new_socket = accept_listen_socket(listen_socket, epollfd);
                        if (new_socket < 0)
				return 8;
                } else {
			if (ev.events & (EPOLLERR  | EPOLLHUP)) {
				verb("socket %d: closed\n", ev.data.fd);
				epoll_op(epollfd, EPOLL_CTL_DEL, EPOLLIN, ev.data.fd);
				close(ev.data.fd);
				if (ev.data.fd == socket_number) {
					verb("parent process closed\n");
					break;
				}
			} else if (ev.events & EPOLLIN) {
				verb("socket %d: incoming message\n", ev.data.fd);
				child = read_incoming_message(ev.data.fd);
				if (!child)
					continue;

				if (start_child(child) == -1) {
					verb("unable to start %s\n", child->argv[0]);
					destroy_child(child);
					continue;
				}

				/* add the child to the list of children */
				child->next = children;
				children = child;
			}
		}
	}

        return 0;
}
