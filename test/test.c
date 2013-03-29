#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <cleave.h>

int main()
{
	struct cleave_handle *handle;
	struct cleave_child *child;

	handle = cleave_create(2);
	assert(handle);

	{
		char const *argv[] = {"/bin/echo", "test", NULL};
		int fd[] = {0, 1, 2};
		pid_t pid;

		child = cleave_child(handle, argv, fd);
		assert(child);
		pid = cleave_wait(child);
		assert(pid == 0);
	}

	// XXX: Use cleave_exec() to start a new cleaved to test cleave_attach()
	//handle = cleave_attach("/tmp/bob");

	cleave_destroy(handle);
	return 0;
}
