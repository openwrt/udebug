#include <sys/stat.h>
#include <sys/socket.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <libubox/usock.h>

#include "server.h"

static struct uloop_fd server_fd;
static char *socket_name;
int debug_level = 3;

static void server_fd_cb(struct uloop_fd *ufd, unsigned int events)
{
	D(3, "cb");
	while (1) {
		int fd = accept(ufd->fd, NULL, 0);
		if (fd < 0) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			return;
		}

		client_alloc(fd);
	}
}

static int usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [options]\n"
		"Options:\n"
		"	-s <name>:		Set path to socket\n"
		"\n", progname);
	return 1;
}

static void mkdir_sockdir(void)
{
	char *sep;

	sep = strrchr(socket_name, '/');
	if (!sep)
		return;

	*sep = 0;
	mkdir(socket_name, 0755);
	*sep = '/';
}

int main(int argc, char **argv)
{
	int ret = -1;
	int ch;

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			socket_name = optarg;
			break;
		default:
			return usage(argv[0]);
		}
	}

	if (!socket_name)
		socket_name = strdup(UDEBUG_SOCK_NAME);

	signal(SIGPIPE, SIG_IGN);

	uloop_init();

	unlink(socket_name);
	mkdir_sockdir();
	umask(0111);
	server_fd.cb = server_fd_cb;
	server_fd.fd = usock(USOCK_UNIX | USOCK_SERVER | USOCK_NONBLOCK, socket_name, NULL);
	if (server_fd.fd < 0) {
		perror("usock");
		goto out;
	}

	uloop_fd_add(&server_fd, ULOOP_READ);
	udebug_ubus_init();
	uloop_run();

out:
	udebug_ubus_free();
	unlink(socket_name);
	uloop_done();

	return ret;
}
