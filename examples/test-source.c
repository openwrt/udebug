#include <stdio.h>
#include <libubox/utils.h>
#include "udebug.h"

static struct udebug ud;
static struct udebug_buf udb;

struct udebug_buf_flag buf_flags[] = {
	{ "enabled", 1ULL }
};
static const struct udebug_buf_meta buf_meta = {
	.name = "counter",
	.format = UDEBUG_FORMAT_STRING,
	.flags = buf_flags,
	.n_flags = ARRAY_SIZE(buf_flags),
};

int main(int argc, char **argv)
{
	int count = 0;

	udebug_init(&ud);
	udebug_connect(&ud, "./udebug.sock");

	udebug_buf_init(&udb, 256, 128);
	udebug_buf_add(&ud, &udb, &buf_meta);
	while (1) {
		udebug_entry_init(&udb);
		udebug_entry_printf(&udb, "count=%d", count++);
		udebug_entry_add(&udb);
		if (count > 10000)
			sleep(1);
	}

	return 0;
}
