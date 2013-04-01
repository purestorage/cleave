#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <cleave.h>

struct test_state {
	char input[1024];
	size_t input_length;
	size_t input_offset;
	char output[1024];
	size_t output_length;
	size_t output_offset;
};

static int state_stdin(int fd, void *priv)
{
	struct test_state *state = priv;
	int ret;

	ret = write(fd, state->input + state->input_offset,
		    state->input_length - state->input_offset);
	if (ret == -1) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		return 1;
	}

	state->input_offset += ret;
	return (state->input_offset == state->input_length);
}

static int state_stdout(int fd, void *priv)
{
	struct test_state *state = priv;
	int ret;

	ret = read(fd, state->output + state->output_offset,
		   state->output_length - state->output_offset);
	if (ret == -1) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		return 1;
	}

	state->output_offset += ret;
	return (state->output_offset == sizeof(state->output));
}

static void logger(char const *format, va_list args)
{
	vfprintf(stderr, format, args);
}

int main()
{
	struct cleave_handle *handle;
	struct cleave_child *child;
	int i;

	cleave_set_logfn(logger);

	/* Test 1: cleave_create */
	handle = cleave_create(2);
	assert(handle);

	/* Test 2: print to stdout via cleave_child/cleave_wait */
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
		char const *argv[] = {"cleaved", "-l", socket, "-d", NULL};
		int fd[] = {0, 1, 2};
		pid_t pid;
		struct cleave_handle *handle_inner;

		child = cleave_child(handle, argv, fd);
		assert(child);

		sleep(1);

		handle_inner = cleave_attach(socket);
		assert(handle_inner);

		/* Test 3: Print to stdout via cleave_exec */
		{
			char const *argv[] = {"/bin/echo", "test3", NULL};
			struct cleave_exec_param param[3];
			pid_t pid;

			memset(&param, 0, sizeof(param));
			for (i = 0; i < 3; i++)
				param[i].dup2_fd = i;

			pid = cleave_exec(handle_inner, argv, param, NULL);
			assert(pid == 0);
		}

		/* Test 4: Provide stdin and stdout via callback */
		{
			char const *argv[] = {"sh", "-c", "cat | cat", NULL};
			struct cleave_exec_param param[3];
			struct test_state state;

			memset(&param, 0, sizeof(param));
			param[0].dup2_fd = -1;
			param[0].rw = state_stdin;
			param[1].dup2_fd = -1;
			param[1].rw = state_stdout;
			param[2].dup2_fd = 2;

			memset(&state, 0, sizeof(state));
			state.input_length = sprintf(state.input, "test4");

			pid = cleave_exec(handle_inner, argv, param, &state);
			assert(pid == 0);

			assert(!strcmp(state.input, state.output));
		}

		/* Test 5: Provice stdin and stdout via iovec */
		{
			char const *argv[] = {"sh", "-c", "cat | cat", NULL};
			struct cleave_exec_param param[3];
			char *input = "test5";
			char output[16];

			memset(&param, 0, sizeof(param));
			param[0].dup2_fd = -1;
			param[0].iov.iov_base = input;
			param[0].iov.iov_len = strlen(input);
			param[1].dup2_fd = -1;
			param[1].iov.iov_base = output;
			param[1].iov.iov_len = sizeof(output);
			param[2].dup2_fd = 2;

			pid = cleave_exec(handle_inner, argv, param, NULL);
			assert(pid == 0);

			assert(param[1].iov.iov_len == strlen(input));
			assert(!memcmp(input, output, strlen(input)));
		}

		cleave_destroy(handle_inner);

		/* Test 4: can we attach again */
		handle_inner = cleave_attach(socket);
		assert(handle_inner);
		cleave_destroy(handle_inner);

		pid = cleave_wait(child);
		assert(pid == 0);
	}

	cleave_destroy(handle);

	/* Verify no fd leaks */
	i = open("/dev/null", O_RDONLY);
	assert(i == 3);

	return 0;
}
