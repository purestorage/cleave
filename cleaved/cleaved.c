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
 * signalfd for SIGHUP
 * better logging
 *...
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

static int epoll_add(int epollfd, int fd)
{
	struct epoll_event ev;

	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		perror("epoll_ctl");
		return -1;
	}

	return 0;
}

static int set_socket_flags(int sock, int new_flags)
{
	 int flags, s;

	 flags = fcntl(sock, F_GETFL, 0);
	 if (flags == -1) {
		 perror ("fcntl");
		 return -1;
	 }

	 flags |= new_flags;
	 s = fcntl(sock, F_SETFL, flags);
	 if (s == -1) {
		 perror ("fcntl");
		 return -1;
	 }

	 return 0;
}

static int setup_listen_socket(char *path)
{
	int sock;
	struct sockaddr_un local;
	int len;

	sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
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

	return 0;
}

/* Accept all incoming connections, adding them to the epollfd */
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

		if (set_socket_flags(in_fd, O_CLOEXEC | O_NONBLOCK))
			return -1;
		if (epoll_add(epollfd, in_fd))
			return -1;
	}

	return 0;
}

static int read_incoming_message(int sock __attribute__((unused)), int epollfd __attribute__((unused)))
{
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
        int  socket_number = 0, accept_socket = 0, ret;

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

        if (!listen_path && !socket_number) {
                usage(argv[0]);
                return 1;
        }

	epollfd = epoll_create(1);
	if (epollfd < 0) {
		perror("epoll_create");
		return 2;
	}
	
        if (socket_number) {
		if (set_socket_flags(socket_number, O_CLOEXEC | O_NONBLOCK))
			return 3;
		if (epoll_add(epollfd, socket_number))
			return 4;
        } else if (listen_path) {
                accept_socket = setup_listen_socket(listen_path);
                if (accept_socket < 0)
                        return 5;
		if (epoll_add(epollfd, accept_socket))
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

                if (ev.data.fd == accept_socket) {
                        int new_socket = accept_listen_socket(accept_socket, epollfd);
                        if (new_socket < 0)
                                return 8;
			if (epoll_add(epollfd, socket_number))
				return 9;

                } else {
			if (read_incoming_message(ev.data.fd, epollfd))
				return 10;
                }
        }

        return 0;
}
