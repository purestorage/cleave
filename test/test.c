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

static void logger(char const *str)
{
	puts(str);
}

int main()
{
	struct cleave_handle *handle;
	struct cleave_child *child;
	struct pollfd pfd;
	int i, status;

	cleave_set_logfn(logger);

	/* Close all file descriptors for test 9 */
	for (i = 3; i < 1024; i++)
		close(i);

	/* Test 1: cleave_create */
	printf("Test 1\n");
	handle = cleave_create(2);
	assert(handle);

	/* Test 2: print to stdout via cleave_child/cleave_wait */
	printf("Test 2\n");
	{
		char const *argv[] = {"/bin/echo", "test", NULL};
		int fd[] = {0, 1, 2};
		pid_t pid;

		child = cleave_child(handle, argv, fd);
		assert(child);
		pid = cleave_wait(child);
		assert(pid == 0);
	}

	{
		/* Test 3: Start cleaved and attach to it */
		char * const socket = "/tmp/cleaved.sock";
		char const *argv[] = {"cleaved/cleaved", "-l", socket, "-d", NULL};
		int fd[] = {0, 1, 2};
		pid_t pid;
		struct cleave_handle *handle_inner;

		printf("Test 3\n");

		child = cleave_child(handle, argv, fd);
		assert(child);

		sleep(1);

		handle_inner = cleave_attach(socket);
		assert(handle_inner);

		status = cleave_destroy(handle_inner);
		assert(WIFEXITED(status));
		assert(WEXITSTATUS(status) == 0);

		/* Test 7: can we attach again */
		printf("Test 7\n");

		handle_inner = cleave_attach(socket);
		assert(handle_inner);

		/* Test 8: Handle an exec failure */
		printf("Test 8\n");
		{
			char const *argv[] = {"does_not_exist", NULL};
			int fd[] = {0, 1, 2};
			struct cleave_child *child2;

			child2 = cleave_child(handle_inner, argv, fd);
			assert(child2 == NULL);
			assert(errno == ENOENT);
		}

		status = cleave_destroy(handle_inner);
		assert(WIFEXITED(status));
		assert(WEXITSTATUS(status) == 0);

		/* Test 9: kill the child and verify the signal is correct */
		printf("Test 9\n");
		pid = cleave_pid(child);
		assert(pid > 0);
		kill(pid, SIGFPE);

		status = cleave_wait(child);
		assert(WIFSIGNALED(status));
		assert(WTERMSIG(status) == SIGFPE);
	}

	/* Test 10: Check that we can wait for cleave to be killed */
	printf("Test 10\n");
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
	int signal = WTERMSIG(status);
	assert(signal == SIGTERM);

	/* Verify no fd leaks */
	i = open("/dev/null", O_RDONLY);
	assert(i == 3);

	return 0;
}
