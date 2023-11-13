#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include "priv.h"

#include <libubox/usock.h>

#define ALIGN(i, sz)	(((i) + (sz) - 1) & ~((sz) - 1))

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#define UDEBUG_MIN_ALLOC_LEN	128
static struct blob_buf b;

static void __randname(char *template)
{
	int i;
	struct timespec ts;
	unsigned long r;

	clock_gettime(CLOCK_REALTIME, &ts);
	r = ts.tv_sec + ts.tv_nsec;
	for (i=0; i<6; i++, r>>=5)
		template[i] = 'A'+(r&15)+(r&16)*2;
}

int udebug_id_cmp(const void *k1, const void *k2, void *ptr)
{
	uint32_t id1 = (uint32_t)(uintptr_t)k1, id2 = (uint32_t)(uintptr_t)k2;
	return id1 - id2;
}

static inline int
shm_open_anon(char *name)
{
	char *template = name + strlen(name) - 6;
	int fd;

	if (template < name || memcmp(template, "XXXXXX", 6) != 0)
		return -1;

	for (int i = 0; i < 100; i++) {
		__randname(template);
		fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
		if (fd >= 0) {
			if (shm_unlink(name) < 0) {
				close(fd);
				continue;
			}
			return fd;
		}

		if (fd < 0 && errno != EEXIST)
			return -1;
	}

	return -1;
}

uint64_t udebug_timestamp(void)
{
	struct timespec ts;
	uint64_t val;

	clock_gettime(CLOCK_REALTIME, &ts);

	val = ts.tv_sec;
	val *= UDEBUG_TS_SEC;
	val += ts.tv_nsec / 1000;

	return val;
}

static int
__udebug_buf_map(struct udebug_buf *buf)
{
	void *ptr, *ptr2;

	ptr = mmap(NULL, buf->head_size + 2 * buf->data_size, PROT_NONE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (ptr == MAP_FAILED)
		return -1;

	ptr2 = mmap(ptr, buf->head_size + buf->data_size,
		    PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, buf->fd, 0);
	if (ptr2 != ptr)
		goto err_unmap;

	ptr2 = mmap(ptr + buf->head_size + buf->data_size, buf->data_size,
		    PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, buf->fd,
		    buf->head_size);
	if (ptr2 != ptr + buf->head_size + buf->data_size)
		goto err_unmap;

	buf->hdr = ptr;
	buf->data = ptr + buf->head_size;
	return 0;

err_unmap:
	munmap(ptr, buf->head_size + 2 * buf->data_size);
	return -1;
}

static int
writev_retry(int fd, struct iovec *iov, int iov_len, int sock_fd)
{
	uint8_t fd_buf[CMSG_SPACE(sizeof(int))] = { 0 };
	struct msghdr msghdr = { 0 };
	struct cmsghdr *cmsg;
	int len = 0;
	int *pfd;

	msghdr.msg_iov = iov,
	msghdr.msg_iovlen = iov_len,
	msghdr.msg_control = fd_buf;
	msghdr.msg_controllen = sizeof(fd_buf);

	cmsg = CMSG_FIRSTHDR(&msghdr);
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));

	pfd = (int *) CMSG_DATA(cmsg);
	msghdr.msg_controllen = cmsg->cmsg_len;

	do {
		ssize_t cur_len;

		if (sock_fd < 0) {
			msghdr.msg_control = NULL;
			msghdr.msg_controllen = 0;
		} else {
			*pfd = sock_fd;
		}

		cur_len = sendmsg(fd, &msghdr, 0);
		if (cur_len < 0) {
			struct pollfd pfd = {
				.fd = fd,
				.events = POLLOUT
			};

			switch(errno) {
			case EAGAIN:
				poll(&pfd, 1, -1);
				break;
			case EINTR:
				break;
			default:
				return -1;
			}
			continue;
		}

		if (len > 0)
			sock_fd = -1;

		len += cur_len;
		while (cur_len >= (ssize_t) iov->iov_len) {
			cur_len -= iov->iov_len;
			iov_len--;
			iov++;
			if (!iov_len)
				return len;
		}
		iov->iov_base += cur_len;
		iov->iov_len -= cur_len;
		msghdr.msg_iov = iov;
		msghdr.msg_iovlen = iov_len;
	} while (1);

	/* Should never reach here */
	return -1;
}

static int
recv_retry(int fd, struct iovec *iov, bool wait, int *recv_fd)
{
	uint8_t fd_buf[CMSG_SPACE(sizeof(int))] = { 0 };
	struct msghdr msghdr = { 0 };
	struct cmsghdr *cmsg;
	int total = 0;
	int bytes;
	int *pfd;

	msghdr.msg_iov = iov,
	msghdr.msg_iovlen = 1,
	msghdr.msg_control = fd_buf;
	msghdr.msg_controllen = sizeof(fd_buf);

	cmsg = CMSG_FIRSTHDR(&msghdr);
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));

	pfd = (int *) CMSG_DATA(cmsg);

	while (iov->iov_len > 0) {
		if (recv_fd) {
			msghdr.msg_control = fd_buf;
			msghdr.msg_controllen = cmsg->cmsg_len;
		} else {
			msghdr.msg_control = NULL;
			msghdr.msg_controllen = 0;
		}

		*pfd = -1;
		bytes = recvmsg(fd, &msghdr, 0);
		if (!bytes)
			return -2;
		if (bytes < 0) {
			bytes = 0;
			if (errno == EINTR)
				continue;

			if (errno != EAGAIN)
				return -2;
		}
		if (!wait && !bytes)
			return 0;

		if (recv_fd)
			*recv_fd = *pfd;
		else if (*pfd >= 0)
			close(*pfd);

		if (bytes > 0)
			recv_fd = NULL;

		wait = true;
		iov->iov_len -= bytes;
		iov->iov_base += bytes;
		total += bytes;

		if (iov->iov_len > 0) {
			struct pollfd pfd = {
				.fd = fd,
				.events = POLLIN
			};
			int ret;
			do {
				ret = poll(&pfd, 1, UDEBUG_TIMEOUT);
			} while (ret < 0 && errno == EINTR);

			if (!(pfd.revents & POLLIN))
				return -1;
		}
	}

	return total;
}

void udebug_send_msg(struct udebug *ctx, struct udebug_client_msg *msg,
		     struct blob_attr *meta, int fd)
{
	struct iovec iov[2] = {
		{ .iov_base = msg, .iov_len = sizeof(*msg) },
		{}
	};

	if (!meta) {
		blob_buf_init(&b, 0);
		meta = b.head;
	}

	iov[1].iov_base = meta;
	iov[1].iov_len = blob_pad_len(meta);
	writev_retry(ctx->fd.fd, iov, ARRAY_SIZE(iov), fd);
}

static void
udebug_buf_msg(struct udebug_buf *buf, enum udebug_client_msg_type type)
{
	struct udebug_client_msg msg = {
		.type = type,
		.id = buf->id,
	};

	udebug_send_msg(buf->ctx, &msg, NULL, -1);
}

static size_t __udebug_headsize(unsigned int ring_size, unsigned int page_size)
{
	ring_size *= sizeof(struct udebug_ptr);
	return ALIGN(sizeof(struct udebug_hdr) + ring_size, page_size);
}

int udebug_buf_open(struct udebug_buf *buf, int fd, uint32_t ring_size, uint32_t data_size)
{
	INIT_LIST_HEAD(&buf->list);
	buf->fd = fd;
	buf->ring_size = ring_size;
	buf->head_size = __udebug_headsize(ring_size, sysconf(_SC_PAGESIZE));
	buf->data_size = data_size;

	if (buf->ring_size > (1U << 24) || buf->data_size > (1U << 29))
		return -1;

	if (__udebug_buf_map(buf))
		return -1;

	if (buf->ring_size != buf->hdr->ring_size ||
		buf->data_size != buf->hdr->data_size) {
		munmap(buf->hdr, buf->head_size + 2 * buf->data_size);
		buf->hdr = NULL;
		return -1;
	}

	return 0;
}

int udebug_buf_init(struct udebug_buf *buf, size_t entries, size_t size)
{
	uint32_t pagesz = sysconf(_SC_PAGESIZE);
	char filename[] = "/udebug.XXXXXX";
	unsigned int order = 12;
	uint8_t ring_order = 5;
	size_t head_size;
	int fd;

	INIT_LIST_HEAD(&buf->list);
	if (size < pagesz)
		size = pagesz;
	while(size > 1 << order)
		order++;
	size = 1 << order;
	while (entries > 1 << ring_order)
		ring_order++;
	entries = 1 << ring_order;

	if (size > (1U << 29) || entries > (1U << 24))
		return -1;

	head_size = __udebug_headsize(entries, pagesz);
	while (ALIGN(sizeof(*buf->hdr) + (entries * 2) * sizeof(struct udebug_ptr), pagesz) == head_size)
		entries *= 2;

	fd = shm_open_anon(filename);
	if (fd < 0)
		return -1;

	if (ftruncate(fd, head_size + size) < 0)
		goto err_close;

	buf->head_size = head_size;
	buf->data_size = size;
	buf->ring_size = entries;
	buf->fd = fd;

	if (__udebug_buf_map(buf))
		goto err_close;

	buf->hdr->ring_size = entries;
	buf->hdr->data_size = size;

	/* ensure hdr changes are visible */
	__sync_synchronize();

	return 0;

err_close:
	close(fd);
	return -1;
}

static void *udebug_buf_alloc(struct udebug_buf *buf, uint32_t ofs, uint32_t len)
{
	struct udebug_hdr *hdr = buf->hdr;

	hdr->data_used = u32_max(hdr->data_used, ofs + len + 1);

	/* ensure that data_used update is visible before clobbering data */
	__sync_synchronize();

	return udebug_buf_ptr(buf, ofs);
}

uint64_t udebug_buf_flags(struct udebug_buf *buf)
{
	struct udebug_hdr *hdr = buf->hdr;
	uint64_t flags;

	if (!hdr)
		return 0;

	flags = hdr->flags[0];
	if (sizeof(flags) != sizeof(uintptr_t))
		flags |= ((uint64_t)hdr->flags[1]) << 32;

	return flags;
}

void udebug_entry_init_ts(struct udebug_buf *buf, uint64_t timestamp)
{
	struct udebug_hdr *hdr = buf->hdr;
	struct udebug_ptr *ptr;

	if (!hdr)
		return;

	ptr = udebug_ring_ptr(hdr, hdr->head);
	ptr->start = hdr->data_head;
	ptr->len = 0;
	ptr->timestamp = timestamp;
}

void *udebug_entry_append(struct udebug_buf *buf, const void *data, uint32_t len)
{
	struct udebug_hdr *hdr = buf->hdr;
	struct udebug_ptr *ptr;
	uint32_t ofs;
	void *ret;

	if (!hdr)
		return NULL;

	ptr = udebug_ring_ptr(hdr, hdr->head);
	ofs = ptr->start + ptr->len;
	if (ptr->len + len > buf->data_size / 2)
		return NULL;

	ret = udebug_buf_alloc(buf, ofs, len);
	if (data)
		memcpy(ret, data, len);
	ptr->len += len;

	return ret;
}

int udebug_entry_printf(struct udebug_buf *buf, const char *fmt, ...)
{
	va_list ap;
	size_t ret;

	va_start(ap, fmt);
	ret = udebug_entry_vprintf(buf, fmt, ap);
	va_end(ap);

	return ret;
}

int udebug_entry_vprintf(struct udebug_buf *buf, const char *fmt, va_list ap)
{
	struct udebug_hdr *hdr = buf->hdr;
	struct udebug_ptr *ptr;
	uint32_t ofs;
	uint32_t len;
	char *str;

	if (!hdr)
		return -1;

	ptr = udebug_ring_ptr(hdr, hdr->head);
	ofs = ptr->start + ptr->len;
	if (ptr->len > buf->data_size / 2)
		return -1;

	str = udebug_buf_alloc(buf, ofs, UDEBUG_MIN_ALLOC_LEN);
	len = vsnprintf(str, UDEBUG_MIN_ALLOC_LEN, fmt, ap);
	if (len <= UDEBUG_MIN_ALLOC_LEN)
		goto out;

	if (ptr->len + len > buf->data_size / 2)
		return -1;

	udebug_buf_alloc(buf, ofs, len + 1);
	len = vsnprintf(str, len, fmt, ap);

out:
	ptr->len += len;
	return 0;
}

void udebug_entry_add(struct udebug_buf *buf)
{
	struct udebug_hdr *hdr = buf->hdr;
	struct udebug_ptr *ptr = udebug_ring_ptr(hdr, hdr->head);
	uint32_t notify;
	uint8_t *data;

	/* ensure strings are always 0-terminated */
	data = udebug_buf_ptr(buf, ptr->start + ptr->len);
	*data = 0;
	hdr->data_head = ptr->start + ptr->len + 1;

	/* ensure that all data changes are visible before advancing head */
	__sync_synchronize();

	u32_set(&hdr->head, u32_get(&hdr->head) + 1);
	if (!u32_get(&hdr->head))
		u32_set(&hdr->head_hi, u32_get(&hdr->head_hi) + 1);

	/* ensure that head change is visible */
	__sync_synchronize();

	notify = __atomic_exchange_n(&hdr->notify, 0, __ATOMIC_RELAXED);
	if (notify) {
		struct udebug_client_msg msg = {
			.type = CL_MSG_RING_NOTIFY,
			.id = buf->id,
			.notify_mask = notify,
		};
		blob_buf_init(&b, 0);

		udebug_send_msg(buf->ctx, &msg, b.head, -1);
	}
}
void udebug_buf_free(struct udebug_buf *buf)
{
	struct udebug *ctx = buf->ctx;

	if (!list_empty(&buf->list) && buf->list.prev)
		list_del(&buf->list);

	if (ctx && ctx->fd.fd >= 0)
		udebug_buf_msg(buf, CL_MSG_RING_REMOVE);

	munmap(buf->hdr, buf->head_size + buf->data_size);
	close(buf->fd);
	memset(buf, 0, sizeof(*buf));
}

static void
__udebug_buf_add(struct udebug *ctx, struct udebug_buf *buf)
{
	struct udebug_client_msg msg = {
		.type = CL_MSG_RING_ADD,
		.id = buf->id,
		.ring_size = buf->hdr->ring_size,
		.data_size = buf->hdr->data_size,
	};
	const struct udebug_buf_meta *meta = buf->meta;
	void *c;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", meta->name);
	c = blobmsg_open_array(&b, "flags");
	for (size_t i = 0; i < meta->n_flags; i++) {
		const struct udebug_buf_flag *flag = &meta->flags[i];
		void *e = blobmsg_open_array(&b, NULL);
		blobmsg_add_string(&b, NULL, flag->name);
		blobmsg_add_u64(&b, NULL, flag->mask);
		blobmsg_close_array(&b, e);
	}
	blobmsg_close_array(&b, c);

	udebug_send_msg(ctx, &msg, b.head, buf->fd);
}

int udebug_buf_add(struct udebug *ctx, struct udebug_buf *buf,
		   const struct udebug_buf_meta *meta)
{
	list_add_tail(&buf->list, &ctx->local_rings);
	buf->ctx = ctx;
	buf->meta = meta;
	buf->id = ctx->next_id++;
	buf->hdr->format = meta->format;
	buf->hdr->sub_format = meta->sub_format;

	if (ctx->fd.fd >= 0)
		__udebug_buf_add(ctx, buf);

	return 0;
}

void udebug_init(struct udebug *ctx)
{
	INIT_LIST_HEAD(&ctx->local_rings);
	avl_init(&ctx->remote_rings, udebug_id_cmp, true, NULL);
	ctx->fd.fd = -1;
	ctx->poll_handle = -1;
}

static void udebug_reconnect_cb(struct uloop_timeout *t)
{
	struct udebug *ctx = container_of(t, struct udebug, reconnect);

	if (udebug_connect(ctx, ctx->socket_path) < 0) {
		uloop_timeout_set(&ctx->reconnect, 1000);
		return;
	}

	udebug_add_uloop(ctx);
}

void udebug_auto_connect(struct udebug *ctx, const char *path)
{
	free(ctx->socket_path);
	ctx->reconnect.cb = udebug_reconnect_cb;
	ctx->socket_path = path ? strdup(path) : NULL;
	if (ctx->fd.fd >= 0)
		return;

	udebug_reconnect_cb(&ctx->reconnect);
}

int udebug_connect(struct udebug *ctx, const char *path)
{
	struct udebug_remote_buf *rb;
	struct udebug_buf *buf;

	if (ctx->fd.fd >= 0)
		close(ctx->fd.fd);
	ctx->fd.fd = -1;

	if (!path)
		path = UDEBUG_SOCK_NAME;

	ctx->fd.fd = usock(USOCK_UNIX, path, NULL);
	if (ctx->fd.fd < 0)
		return -1;

	list_for_each_entry(buf, &ctx->local_rings, list)
		__udebug_buf_add(ctx, buf);

	avl_for_each_element(&ctx->remote_rings, rb, node) {
		if (!rb->poll)
			continue;

		rb->poll = false;
		udebug_remote_buf_set_poll(ctx, rb, true);
	}

	return 0;
}

static bool
udebug_recv_msg(struct udebug *ctx, struct udebug_client_msg *msg, int *fd,
		bool wait)
{
	struct iovec iov = {
		.iov_base = msg,
		.iov_len = sizeof(*msg)
	};
	int ret;

	ret = recv_retry(ctx->fd.fd, &iov, wait, fd);
	if (ret == -2)
		uloop_fd_delete(&ctx->fd);

	return ret == sizeof(*msg);
}

struct udebug_client_msg *__udebug_poll(struct udebug *ctx, int *fd, bool wait)
{
	static struct udebug_client_msg msg = {};

	while (udebug_recv_msg(ctx, &msg, fd, wait)) {
		struct udebug_remote_buf *rb;
		void *key;

		if (msg.type != CL_MSG_RING_NOTIFY)
			return &msg;

		if (fd && *fd >= 0)
			close(*fd);

		if (!ctx->notify_cb)
			continue;

		key = (void *)(uintptr_t)msg.id;
		rb = avl_find_element(&ctx->remote_rings, key, rb, node);
		if (!rb || !rb->poll)
			continue;

		if (ctx->poll_handle >= 0)
			__atomic_fetch_or(&rb->buf.hdr->notify,
					  1UL << ctx->poll_handle,
					  __ATOMIC_RELAXED);
		ctx->notify_cb(ctx, rb);
	}

	return NULL;
}

void udebug_poll(struct udebug *ctx)
{
	while (__udebug_poll(ctx, NULL, false));
}

static void udebug_fd_cb(struct uloop_fd *fd, unsigned int events)
{
	struct udebug *ctx = container_of(fd, struct udebug, fd);

	if (fd->eof)
		uloop_fd_delete(fd);

	udebug_poll(ctx);
}

void udebug_add_uloop(struct udebug *ctx)
{
	if (ctx->fd.registered)
		return;

	ctx->fd.cb = udebug_fd_cb;
	uloop_fd_add(&ctx->fd, ULOOP_READ);
}

void __udebug_disconnect(struct udebug *ctx, bool reconnect)
{
	uloop_fd_delete(&ctx->fd);
	close(ctx->fd.fd);
	ctx->fd.fd = -1;
	ctx->poll_handle = -1;
	if (ctx->reconnect.cb)
		uloop_timeout_set(&ctx->reconnect, 1);
}

void udebug_free(struct udebug *ctx)
{
	struct udebug_remote_buf *rb, *tmp;
	struct udebug_buf *buf;

	free(ctx->socket_path);
	ctx->socket_path = NULL;

	__udebug_disconnect(ctx, false);

	while (!list_empty(&ctx->local_rings)) {
		buf = list_first_entry(&ctx->local_rings, struct udebug_buf, list);
		udebug_buf_free(buf);
	}

	avl_for_each_element_safe(&ctx->remote_rings, rb, node, tmp)
		udebug_remote_buf_unmap(ctx, rb);
}
