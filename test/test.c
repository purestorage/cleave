#include <cleave.h>
#include <assert.h>

int main()
{
	struct cleave_handle * handle;

	handle = cleave_create();
	assert(handle);

	// XXX: Use cleave_exec() to start a new cleaved to test cleave_attach()
	//handle = cleave_attach("/tmp/bob");

	cleave_destroy(handle);
	return 0;
}
