#include <cleave.h>
#include <assert.h>

int main()
{
	struct cleave_handle * handle;

	handle = cleave_create();
	assert(handle);

	cleave_destroy(handle);
	return 0;
}
