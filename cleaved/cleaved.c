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
#define _GNU_SOURCE
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <stdarg.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/signalfd.h>

struct list_head {
	struct list_head *prev;
	struct list_head *next;
};

struct child_proc {
	struct list_head list;
	char **argv;
	int fd[3];
	int exit_pipe;
	pid_t pid;
	struct ucred uc;
};

static int epollfd;
static int sigfd;
static int debug;
struct list_head children;
static FILE *logfile;

/********************* Logging **********************/

static void
cleaved_log(char const *format, const char *level, va_list args)
{
	time_t t;
	struct tm *tm;
	char s[40];

	t = time(NULL);
	tm = localtime(&t);
	strftime(s, sizeof(s), "%b %e %H:%M:%S", tm);

	fprintf(logfile, "%s cleaved[%s]: ", s, level);
	vfprintf(logfile, format, args);
	fflush(logfile);
}

static void __attribute__((format (printf, 1, 2)))
cleaved_log_err(char const *format, ...)
{
	va_list args;

	va_start(args, format);
	cleaved_log(format, "ERR", args);
	va_end(args);
}

static void
cleaved_perror(const char *s)
{
	cleaved_log_err("%s: %s\n", s, strerror(errno));
}

static void __attribute__((format (printf, 1, 2)))
cleaved_log_msg(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	cleaved_log(format, "MSG", args);
	va_end(args);
}

static void  __attribute__((format (printf, 1, 2)))
cleaved_log_dbg(const char *format, ...)
{
	va_list args;

	if (!debug)
		return;

	va_start(args, format);
	cleaved_log(format, "DBG", args);
	va_end(args);
}

static void
reopen_logfile(char const *name)
{
	if (name) {
		if (fflush(logfile))
			cleaved_perror("fflush");
		if (logfile != stderr && fclose(logfile))
			cleaved_perror("fclose");
	}
	if (!name)
		logfile = stderr;
	else {
		logfile = fopen(name, "a");
		if (!logfile) {
			logfile = stderr;
			cleaved_perror("fopen");
		}
	}
}

/********************* List handling *******************/

#define offsetof(_type, _member) ((size_t) &((_type *)0)->_member)

#define list_entry(_ptr, _type, _member)			\
	((_type *)((char *)(_ptr) - offsetof(_type, _member)))

static void list_init(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static void __list_add(struct list_head *new,
		       struct list_head *prev,
		       struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

static void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, __typeof__(*pos), member);	\
	     &pos->member != head;					\
	     pos = list_entry(pos->member.next, __typeof__(*pos), member))

/********************* Operations **********************/

static void  __attribute__((noreturn))
out_of_memory()
{
	cleaved_log_err("out of memory");
	abort();
}

static int epoll_op(int op, int flags, int fd)
{
	struct epoll_event ev;

	ev.events = flags;
	ev.data.fd = fd;
	if (epoll_ctl(epollfd, op, fd, &ev) == -1) {
		cleaved_perror("epoll_ctl");
		return -1;
	}

	return 0;
}

static int do_fcntl(int sock, int get, int set, int add_flags, int del_flags)
{
	 int flags, s;

	 flags = fcntl(sock, get, 0);
	 if (flags == -1) {
		 cleaved_perror("fcntl");
		 return -1;
	 }
	 flags = (flags | add_flags) & ~del_flags;
	 s = fcntl(sock, set, flags);
	 if (s == -1) {
		 cleaved_perror("fcntl");
		 return -1;
	 }

	 return 0;
}

static ssize_t do_write(int fd, const void * buf, size_t size)
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
		} else {
			*pret++ = *pstr;
		}
		pstr++;
	}
	*pret = '\0';
	return pret - ret;
}

/********************* Socket handling **********************/

static int setup_listen_socket(char *path)
{
	int sock;
	struct sockaddr_un local;
	int len;

	sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (sock == -1) {
		cleaved_perror("socket");
		return -1;
	}
	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, path);
	unlink(path); // ignore error
	len = strlen(local.sun_path) + sizeof(local.sun_family);
	if (bind(sock, (struct sockaddr *)&local, len) == -1) {
		cleaved_perror("bind");
		return -1;
	}
	if (listen(sock, 5) == -1) {
		cleaved_perror("listen");
		return -1;
	}

	return sock;
}

static int accept_listen_socket(int socket)
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
			cleaved_perror("accept");
			return -1;
		}

		if (do_fcntl(in_fd, F_GETFD, F_SETFD, O_CLOEXEC, 0) ||
		    do_fcntl(in_fd, F_GETFL, F_SETFL, O_NONBLOCK, 0) ||
		    epoll_op(EPOLL_CTL_ADD, EPOLLIN, in_fd)) {
			close(in_fd);
			return -1;
		}
		cleaved_log_dbg("socket %d: connected\n", in_fd);
	}

	return 0;
}

/* Message consists of
 *   exec=urlencode(argv[0])&arg=urlencode(argv[1])&arg=urlencode(argv[2])\n
 */
static int decode_message(struct child_proc *child, char *buf)
{
	int argcount, bufsize;
	char **argv, *pbuf, *argbuf, *bufend;

	if (strncmp(buf, "exec=", 5)) {
		cleaved_log_dbg("unknown message type\n");
		return -1;
	}
	buf += 5;

	/* Count the number of arguments in first line */
	for (pbuf = buf, argcount = 0; *pbuf; pbuf++) {
		if (!strncmp(pbuf, "&a=", 3) || *pbuf == '\n') {
			++argcount;
			if (*pbuf == '\n')
				break;
			pbuf += 2;
		}
	}
	bufsize = pbuf - buf;
	bufend = pbuf;

	argv = malloc(sizeof(char *) * (argcount + 1));
	if (!argv)
		out_of_memory();

	/* Allocate a single buffer for all of the decoded strings, which
	 * is guaranteed to be less than the number of bytes above */
	argbuf = malloc(bufsize);
	if (!argbuf)
		out_of_memory();

	/* Start decoding the mesage */
	pbuf = buf;
	argcount = 0;
	while (*pbuf) {
		assert(pbuf <= bufend);
		if (!strncmp(pbuf, "&a=", 3) || *pbuf == '\n') {
			int terminal = (*pbuf == '\n');
			/* Split the incoming argument */
			*pbuf = '\0';
			/* Decode the argument (and NUL) into argbuf. */
			argv[argcount++] = argbuf;
			argbuf += urldecode(buf, argbuf) + 1;
			if (terminal)
				break;
			pbuf = buf = pbuf + 3;
		} else
			pbuf++;
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
	int fd[4], ret, readbuflen;
	size_t nfd = 0, i;
	char cmsgbuf[CMSG_SPACE(sizeof(fd))];
	struct iovec data;
	struct msghdr hdr;
	struct cmsghdr *cmsg;
	socklen_t optlen;
	char *readbuf;

	// The maximum size of message we can receive is given by the SO_SNDBUF * 2
	optlen = sizeof(readbuflen);
	if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &readbuflen, &optlen) == -1) {
		perror("getsockopt");
		return NULL;
	}
	readbuflen <<= 1;
	readbuf = malloc(readbuflen);
	if (!readbuf)
		out_of_memory();

	child = malloc(sizeof(struct child_proc));
	if (!child)
		out_of_memory();
	memset(child, 0, sizeof(*child));

	data.iov_base = readbuf;
	data.iov_len = readbuflen;

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
		cleaved_perror("recvmsg");
		goto exit_recvmsg;
	}

	if (hdr.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) {
		cleaved_log_dbg("recvmsg truncated\n");
		goto exit_recvmsg;
	}

	cmsg = CMSG_FIRSTHDR(&hdr);
	nfd = (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(fd[0]);
	if (nfd != 4) {
		cleaved_log_dbg("incorrect number of file descriptors %d\n", (int)nfd);
		goto exit_recvmsg;
	}

	if (decode_message(child, readbuf) == -1)
		goto exit_recvmsg;

	optlen = sizeof(child->uc);
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &child->uc, &optlen) == -1)
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
	free(readbuf);
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

static int start_child(struct child_proc *child)
{
	int err_pipe[2], ret;
	sigset_t sigmask;
	pid_t pid;
	char buf[16];

	if (pipe2(err_pipe, O_CLOEXEC) == -1) {
		perror("pipe2");
		return -1;
	}

	pid = fork();
	if (pid == -1) {
		perror("fork");
		if (close(err_pipe[0]) || close(err_pipe[1]))
			perror("close");
		return -1;
	} else if (pid == 0) {
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

		/* Unblock signals blocked in parent process */
		sigfillset(&sigmask);
		if (sigprocmask(SIG_UNBLOCK, &sigmask, NULL) == -1)
			goto child_error;

		if (geteuid() == 0) {
			/* Switch to the connecting credentials */
			if (setgid(child->uc.gid) || setuid(child->uc.uid))
				goto child_error;
		}

		execvp(child->argv[0], child->argv);
	child_error:
		do_write(err_pipe[1], buf, sprintf(buf, "errno=%d\n", errno));
		_exit(127);
	}

	/* parent */
	close(err_pipe[1]);
	close(child->fd[0]);
	close(child->fd[1]);
	close(child->fd[2]);
	child->fd[0] = child->fd[1] = child->fd[2] = -1;
	child->pid = pid;

	/* send the pid= or the errno= back to the client */
	ret = read(err_pipe[0], buf, sizeof(buf));
	if (ret) {
		do_write(child->exit_pipe, buf, ret);
		close(err_pipe[0]);
		return -1;
	}

	close(err_pipe[0]);
	do_write(child->exit_pipe, buf, sprintf(buf, "pid=%d\n", pid));
	list_add(&child->list, &children);

	cleaved_log_msg("started %s pid %d\n", child->argv[0], pid);

	return 0;
}

/* One or more child processes has finished. reap and notify */
static int reap_child()
{
	struct child_proc *child;
	char buf[16];
	int status;
	pid_t pid;

next_child:
	pid = waitpid(-1, &status, WNOHANG);
	if (pid <= 0) {
		return 0;
	}

	cleaved_log_dbg("pid %d completed status %d\n", pid, status);
	list_for_each_entry(child, &children, list) {
		if (child->pid == pid) {
			list_del(&child->list);
			/* notify the client */
			do_write(child->exit_pipe, buf, sprintf(buf, "rc=%d\n", status));
			destroy_child(child);
			goto next_child;
		}
	}
	cleaved_log_err("unknown child pid %d completed\n", pid);
	return -1;
}

static int setup_event_fds()
{
	unsigned		sig;
	struct sigaction	sa;

	epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (epollfd < 0) {
		cleaved_perror("epoll_create");
		return -1;
	}

	/* Reset all signal handlers to default */
	sa.sa_flags = 0;
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	for (sig = 0; sig < NSIG; sig++)
		sigaction(sig, &sa, NULL);

	/* Block the signals used with signalfd */
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGHUP);
	sigaddset(&sa.sa_mask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &sa.sa_mask, NULL) < 0) {
		cleaved_perror("sigprocmask");
		return -1;
	}

	sigfd = signalfd(-1, &sa.sa_mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sigfd < 0) {
		cleaved_perror("signalfd");
		return -1;
	}

	if (epoll_op(EPOLL_CTL_ADD, EPOLLIN, sigfd))
		return -1;

	return 0;
}

static void usage(char const *prog)
{
	printf("Usage:\n");
	printf("  %s	 fork/exec daemon\n", prog);
	printf("\n");
	printf("Options:\n");
	printf("  -l, --listen=<path>     open a unix domain socket at the given path\n");
	printf("  -n, --number=<fd>       start listening on the given socket number\n");
	printf("  -o, --logfile=<path>    path for logging. SIGHUP is supported\n");
	printf("  -d, --debug	     enable debug logging\n");
	printf("  -h, --help	      print this usage information and exit\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	struct epoll_event ev;
	char *listen_path = NULL, *logfile_name = NULL;
	int  socket_number = -1, listen_socket = -1, ret;
	struct child_proc *child;

	logfile = stderr;

	while (1) {
		int c;

		static struct option long_options[] = {
			{ .name = "listen",     .has_arg = required_argument,   .val = 'l' },
			{ .name = "number",     .has_arg = required_argument,   .val = 'n' },
			{ .name = "logfile",    .has_arg = required_argument,   .val = 'o' },
			{ .name = "debug",      .has_arg = no_argument,	 .val = 'd' },
			{ .name = "help",       .has_arg = no_argument,	 .val = 'h' },
			{ 0 },
		};

		c = getopt_long(argc, argv, "l:n:o:dh", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'l':
			listen_path = strdupa(optarg);
			break;
		case 'n':
			socket_number = atoi(optarg);
			break;
		case 'o':
			logfile_name = strdupa(optarg);
			break;
		case 'd':
			debug = 1;
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

	reopen_logfile(logfile_name);

	if (setup_event_fds())
		return 2;

	if (socket_number != -1) {
		if (do_fcntl(socket_number, F_GETFD, F_SETFD, FD_CLOEXEC, 0) ||
		    do_fcntl(socket_number, F_GETFL, F_SETFL, O_NONBLOCK, 0))
			return 3;
		if (epoll_op(EPOLL_CTL_ADD, EPOLLIN, socket_number))
			return 4;
	} else if (listen_path) {
		listen_socket = setup_listen_socket(listen_path);
		if (listen_socket < 0)
			return 5;
		if (epoll_op(EPOLL_CTL_ADD, EPOLLIN, listen_socket))
			return 6;
	}

	list_init(&children);

	/* Main event loop */

	while (1) {
		ret = epoll_wait(epollfd, &ev, 1, -1);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			cleaved_perror("epoll_wait");
			return 7;
		}
		if (ret == 0)
			continue;

		if (ev.data.fd == listen_socket) {
			int new_socket = accept_listen_socket(listen_socket);
			if (new_socket < 0)
				return 8;
		} else if (ev.data.fd == sigfd) {
			struct signalfd_siginfo	si;

			if (read(sigfd, &si, sizeof si) < (int)sizeof(si)) {
				cleaved_perror("read");
				return 9;
			}
			if (si.ssi_signo == SIGHUP) {
				reopen_logfile(logfile_name);

			} else if (si.ssi_signo == SIGCHLD) {
				if (reap_child() == -1) {
					return 10;
				}
			}
		} else {
			if (ev.events & (EPOLLERR  | EPOLLHUP)) {
				cleaved_log_dbg("socket %d: closed\n", ev.data.fd);
				close(ev.data.fd);
				if (ev.data.fd == socket_number) {
					cleaved_log_msg("parent process closed. exiting\n");
					break;
				}
			} else if (ev.events & EPOLLIN) {
				cleaved_log_dbg("socket %d: incoming message\n", ev.data.fd);
				child = read_incoming_message(ev.data.fd);
				if (child) {
					if (start_child(child) == -1) {
						cleaved_log_err("unable to start %s\n", child->argv[0]);
						destroy_child(child);
					}
				}
			}
		}
	}

	return 0;
}
