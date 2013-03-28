/*
 * simple wrappers and syscalls to retry after EINTR
 *
 * Copyright © 2013 Pure Storage, Inc.
 *
 * This program is free software; you may redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "syscall.h"

int do_close(int sock)
{
	int ret;
again:
	ret = close(sock);
	if (ret == -1 && errno == EINTR)
		goto again;
	return ret;
}

int do_connect(int sockfd, const struct sockaddr *addr,
	       socklen_t addrlen)
{
	int ret;
again:
	ret = connect(sockfd, addr, addrlen);
	if (ret == -1 && errno == EINTR)
		goto again;
	return ret;
}

pid_t do_waitpid(pid_t pid, int *status, int options)
{
	pid_t ret;
again:
	ret = waitpid(pid, status, options);
	if (ret == -1 && errno == EINTR)
		goto again;
	return ret;
}

ssize_t do_write(int fd, const void * buf, size_t size)
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

ssize_t do_read(int fd, void *buf, size_t size)
{
	int ret;
again:
	ret = read(fd, buf, size);
	if (ret == -1 && errno == EINTR)
		goto again;
	return ret;
}
