#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <cleave.h>

static char * const socket = "/tmp/cleaved.sock";

static void logger(char const *str)
{
	puts(str);
}

/* test: cleave_create */
static struct cleave_handle * test1(void)
{
	struct cleave_handle *handle;

	printf("Test 1\n");
	handle = cleave_create(2);
	assert(handle);

	return handle;
}

/* test: print to stdout via cleave_child/cleave_wait */
static void test2(struct cleave_handle *handle)
{
	struct cleave_child *child;
	char const *argv[] = {"/bin/echo", "test", NULL};
	int fd[] = {0, 1, 2};
	pid_t pid;

	printf("Test 2\n");

	child = cleave_child(handle, argv, fd);
	assert(child);
	pid = cleave_wait(child);
	assert(pid == 0);
}

/* test: Start cleaved and attach to it */
static struct cleave_child *test3(struct cleave_handle *handle)
{
	char const *argv[] = {"cleaved/cleaved", "-l", socket, "-d", NULL};
	int fd[] = {0, 1, 2};
	struct cleave_child *child;
	struct cleave_handle *handle_inner;
	int status;

	printf("Test 3\n");

	child = cleave_child(handle, argv, fd);
	assert(child);

	sleep(1);

	handle_inner = cleave_attach(socket);
	assert(handle_inner);

	status = cleave_destroy(handle_inner);
	assert(WIFEXITED(status));
	assert(WEXITSTATUS(status) == 0);
	return child;
}

/* test: can we attach again */
static struct cleave_handle *test4(void)
{
	struct cleave_handle *handle;

	printf("Test 4\n");

	handle = cleave_attach(socket);
	assert(handle);

	return handle;
}

/* test: exec failure */
static void test5(struct cleave_handle *handle)
{
	char const *argv[] = {"does_not_exist", NULL};
	int fd[] = {0, 1, 2};
	struct cleave_child *child;

	printf("Test 5\n");

	child = cleave_child(handle, argv, fd);
	assert(child == NULL);
	assert(errno == ENOENT);
}

/* test: kill child and check return code */
static void test6(struct cleave_child *child, struct cleave_handle *child2)
{
	int signal;
	int status;
	int pid;

	printf("Test 6\n");

	status = cleave_destroy(child2);
	assert(WIFEXITED(status));
	assert(WEXITSTATUS(status) == 0);

	pid = cleave_pid(child);
	assert(pid > 0);
	kill(pid, SIGFPE);

	status = cleave_wait(child);
	assert(WIFSIGNALED(status));
	signal = WTERMSIG(status);
	assert(signal == SIGFPE);
}

/* test: check that we can wait for cleave to be killed */
static void test7(struct cleave_handle *handle)
{
	struct pollfd pfd;
	int signal;
	int status;

	printf("Test 7\n");

	pfd.fd = cleave_connect_fd(handle);
	pfd.events = POLLRDHUP | POLLHUP;
	pfd.revents = 0;
	assert(poll(&pfd, 1, 0) == 0);

	assert(system("killall cleaved") == 0);

	pfd.fd = cleave_connect_fd(handle);
	pfd.events = POLLRDHUP | POLLHUP;
	pfd.revents = 0;
	assert(poll(&pfd, 1, 0) == 1);

	status = cleave_destroy(handle);
	assert(WIFSIGNALED(status));
	signal = WTERMSIG(status);
	assert(signal == SIGTERM);
}

int main()
{
	struct cleave_handle *handle;
	struct cleave_child *child;
	struct cleave_handle *child2;
	int i;

	cleave_set_logfn(logger);

	/* Close all file descriptors for test 9 */
	for (i = 3; i < 1024; i++)
		close(i);

	handle = test1();
	test2(handle);
	child = test3(handle);
	child2 = test4();
	test5(child2);
	test6(child, child2);
	test7(handle);

	/* Verify no fd leaks */
	i = open("/dev/null", O_RDONLY);
	assert(i == 3);

	return 0;
}
