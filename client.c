#define _GNU_SOURCE
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#ifdef linux
#include <linux/sockios.h>
#endif
#ifdef __APPLE__
#include <libproc.h>
#endif

#include "server.h"

#define UDEBUG_SNDBUF	65536

static LIST_HEAD(clients);

static void client_send_msg(struct client *cl, struct udebug_client_msg *data, int fd)
{
	uint8_t fd_buf[CMSG_SPACE(sizeof(int))] = { 0 };
	struct iovec iov = {
		.iov_base = data,
		.iov_len = sizeof(*data),
	};
	struct msghdr msg = {
		.msg_control = fd_buf,
		.msg_controllen = sizeof(fd_buf),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	struct cmsghdr *cmsg;
	int buffered = 0;
	int *pfd;
	int len;

#ifdef linux
	ioctl(cl->fd.fd, SIOCOUTQ, &buffered);
#elif defined(__APPLE__)
	socklen_t slen = sizeof(buffered);
	getsockopt(cl->fd.fd, SOL_SOCKET, SO_NWRITE, &buffered, &slen);
#endif

	DC(3, cl, "send msg type=%d len=%d, fd=%d",
	  data->type, (unsigned int)iov.iov_len, fd);

	if (buffered > UDEBUG_SNDBUF / 2) {
		DC(3, cl, "skip message due to limited buffer size");
		return;
	}

	if (fd >= 0) {
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		msg.msg_controllen = cmsg->cmsg_len;

		pfd = (int *)CMSG_DATA(cmsg);
		*pfd = fd;
	} else {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}

	do {
		len = sendmsg(cl->fd.fd, &msg, 0);
	} while (len < 0 && errno == EINTR);
}

static int client_alloc_notify_id(void)
{
	struct client *cl;
	uint32_t mask = 0;

	list_for_each_entry(cl, &clients, list)
		if (cl->notify_id >= 0)
			mask |= 1 << cl->notify_id;

	for (int i = 0; i < 32; i++, mask >>= 1)
		if (!(mask & 1))
			return i;

	return 31;
}

static void client_msg_get_handle(struct client *cl)
{
	struct udebug_client_msg msg = {
		.type = CL_MSG_GET_HANDLE,
	};

	if (cl->notify_id < 0 && cl->uid == 0)
		cl->notify_id = client_alloc_notify_id();

	msg.id = cl->notify_id;
	client_send_msg(cl, &msg, -1);
}

static void client_msg_ring_get(struct client *cl, uint32_t id)
{
	struct udebug_client_msg msg = {
		.type = CL_MSG_RING_GET,
		.id = id,
	};
	struct client_ring *r = ring_get_by_id(id);
	int fd = -1;

	if (!r || cl->uid != 0) {
		DC(2, cl, "could not get ring %x", id);
		goto out;
	}

	fd = r->fd;
	msg.ring_size = r->ring_size;
	msg.data_size = r->data_size;

out:
	client_send_msg(cl, &msg, fd);
}

static void client_msg_notify(struct client_ring *r, uint32_t mask)
{
	struct udebug_client_msg msg = {
		.type = CL_MSG_RING_NOTIFY,
		.id = ring_id(r),
		.notify_mask = mask,
	};
	struct client *cl;

	list_for_each_entry(cl, &clients, list) {
		if (cl->notify_id < 0 ||
		    !(mask & (1 << cl->notify_id)))
			continue;

		client_send_msg(cl, &msg, -1);
	}
}

static void client_free(struct client *cl)
{
	struct client_ring *r;

	while (!list_empty(&cl->bufs)) {
		r = list_first_entry(&cl->bufs, struct client_ring, list);
		client_ring_free(r);
	}

	DC(2, cl, "disconnect");
	uloop_fd_delete(&cl->fd);
	close(cl->fd.fd);
	list_del(&cl->list);

	free(cl);
}

static void client_parse_message(struct client *cl)
{
	struct udebug_client_msg *msg = &cl->rx_buf.msg;
	struct client_ring *r;

	DC(3, cl, "msg type=%d len=%d", msg->type, (unsigned int)cl->rx_ofs);
	switch (msg->type) {
	case CL_MSG_RING_ADD:
		client_ring_alloc(cl);
		client_send_msg(cl, msg, -1);
		break;
	case CL_MSG_RING_REMOVE:
		DC(2, cl, "delete ring %x", msg->id);
		r = client_ring_get_by_id(cl, msg->id);
		if (r)
			client_ring_free(r);
		else
			DC(2, cl, "ring not found");
		client_send_msg(cl, msg, -1);
		break;
	case CL_MSG_RING_NOTIFY:
		DC(3, cl, "notify on ring %d", msg->id);
		r = client_ring_get_by_id(cl, msg->id);
		if (r)
			client_msg_notify(r, msg->notify_mask);
		else
			DC(2, cl, "local ring %d not found", msg->id);
		break;
	case CL_MSG_GET_HANDLE:
		client_msg_get_handle(cl);
		DC(2, cl, "get notify handle: %d", cl->notify_id);
		break;
	case CL_MSG_RING_GET:
		DC(2, cl, "get ring %x", msg->id);
		client_msg_ring_get(cl, msg->id);
		break;
	default:
		DC(3, cl, "Invalid message type %d", msg->type);
		break;
	}

	if (cl->rx_fd < 0)
		return;

	close(cl->rx_fd);
	cl->rx_fd = -1;
}

static void client_fd_cb(struct uloop_fd *fd, unsigned int events)
{
	struct client *cl = container_of(fd, struct client, fd);
	uint8_t fd_buf[CMSG_SPACE(sizeof(int))] = {};
	struct iovec iov = {};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = fd_buf,
		.msg_controllen = sizeof(fd_buf),
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	size_t min_sz = sizeof(cl->rx_buf.msg) + sizeof(struct blob_attr);
	ssize_t len;
	int *pfd;

	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));

	pfd = (int *)CMSG_DATA(cmsg);
	msg.msg_controllen = cmsg->cmsg_len;

retry:
	*pfd = -1;
	if (fd->eof) {
		client_free(cl);
		return;
	}

	iov.iov_base = &cl->rx_buf;
	iov.iov_len = min_sz;
	if (!cl->rx_ofs) {
		iov.iov_base = &cl->rx_buf.msg;
		iov.iov_len = min_sz;

		len = recvmsg(fd->fd, &msg, 0);
		if (len < 0)
			return;
		if (!len)
			fd->eof = true;

		cl->rx_ofs = len;
		cl->rx_fd = *pfd;
		goto retry;
	} else if (cl->rx_ofs >= min_sz) {
		iov.iov_len += blob_pad_len(&cl->rx_buf.data);
		iov.iov_len -= sizeof(struct blob_attr);
		if (iov.iov_len > sizeof(cl->rx_buf)) {
			client_free(cl);
			return;
		}
	}

	iov.iov_base += cl->rx_ofs;
	iov.iov_len -= cl->rx_ofs;
	if (iov.iov_len) {
		len = read(fd->fd, iov.iov_base, iov.iov_len);
		if (len <= 0)
			return;

		cl->rx_ofs += len;
		goto retry;
	}

	client_parse_message(cl);
	cl->rx_ofs = 0;
	goto retry;
}

static void client_get_info(struct client *cl)
{
#ifdef LOCAL_PEERPID
	socklen_t len = sizeof(&cl->pid);
	if (getsockopt(cl->fd.fd, SOL_LOCAL, LOCAL_PEERPID, &cl->pid, &len) < 0)
		return;
#elif defined(SO_PEERCRED)
	struct ucred uc;
	socklen_t len = sizeof(uc);
	if (getsockopt(cl->fd.fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) < 0)
		return;
	cl->pid = uc.pid;
	cl->uid = uc.uid;
#endif
}

static void client_get_procname(struct client *cl)
{
#ifdef linux
	char buf[256];
	FILE *f;

	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", cl->pid);
	f = fopen(buf, "r");
	if (!f)
		return;
	buf[fread(buf, 1, sizeof(buf) - 1, f)] = 0;
	fclose(f);
	snprintf(cl->proc_name, sizeof(cl->proc_name), "%s", basename(buf));
#endif
#ifdef __APPLE__
	proc_name(cl->pid, cl->proc_name, sizeof(cl->proc_name) - 1);
#endif
}

void client_alloc(int fd)
{
	int sndbuf = UDEBUG_SNDBUF;
	struct client *cl;

	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

	cl = calloc(1, sizeof(*cl));
	INIT_LIST_HEAD(&cl->bufs);
	cl->fd.fd = fd;
	cl->fd.cb = client_fd_cb;
	cl->rx_fd = -1;
	client_get_info(cl);
	if (cl->pid)
		client_get_procname(cl);
	if (!cl->proc_name[0])
		snprintf(cl->proc_name, sizeof(cl->proc_name), "<unknown>");

	DC(2, cl, "connect");
	uloop_fd_add(&cl->fd, ULOOP_READ);
	list_add_tail(&cl->list, &clients);
}
