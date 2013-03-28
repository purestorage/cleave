/*
 * libcleave: fork/exec daemon
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
#ifndef _SYSCALL_H
#define _SYSCALL_H

int do_close(int sock);
int do_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
ssize_t do_write(int fd, const void *buf, size_t count);
ssize_t do_read(int fd, void *buf, size_t count);
pid_t do_waitpid(pid_t pid, int *status, int options);

#endif
