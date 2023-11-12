#ifndef __UDEBUG_UTIL_H
#define __UDEBUG_UTIL_H

#include <libubox/blobmsg.h>
#include "udebug.h"

#define UDEBUG_TIMEOUT	1000

struct udebug_hdr {
	uint32_t ring_size;
	uint32_t data_size;

	uint32_t format;
	uint32_t sub_format;

	uintptr_t flags[8 / sizeof(uintptr_t)];
	uintptr_t notify;

	uint32_t head_hi;
	uint32_t head;
	uint32_t data_head;
	uint32_t data_used;
};

enum udebug_client_msg_type {
	CL_MSG_RING_ADD,
	CL_MSG_RING_REMOVE,
	CL_MSG_RING_NOTIFY,
	CL_MSG_GET_HANDLE,
	CL_MSG_RING_GET,
	CL_MSG_ERROR,
};

struct udebug_client_msg {
	uint8_t type;
	uint8_t _pad[3];
	uint32_t id;
	union {
		struct {
			uint32_t ring_size, data_size;
		};
		uint32_t notify_mask;
	};
} __attribute__((packed, aligned(4)));

static inline struct udebug_ptr *
udebug_ring_ptr(struct udebug_hdr *hdr, uint32_t idx)
{
	struct udebug_ptr *ring = (struct udebug_ptr *)&hdr[1];
	return &ring[idx & (hdr->ring_size - 1)];
}

static inline void *udebug_buf_ptr(struct udebug_buf *buf, uint32_t ofs)
{
	return buf->data + (ofs & (buf->data_size - 1));
}

int udebug_id_cmp(const void *k1, const void *k2, void *ptr);
__hidden int udebug_buf_open(struct udebug_buf *buf, int fd, uint32_t ring_size, uint32_t data_size);
__hidden struct udebug_client_msg *__udebug_poll(struct udebug *ctx, int *fd, bool wait);
__hidden void udebug_send_msg(struct udebug *ctx, struct udebug_client_msg *msg,
		     struct blob_attr *meta, int fd);
__hidden void __udebug_disconnect(struct udebug *ctx, bool reconnect);

static inline int32_t u32_sub(uint32_t a, uint32_t b)
{
	return a - b;
}

static inline int32_t u32_max(uint32_t a, uint32_t b)
{
	return u32_sub(a, b) > 0 ? a : b;
}

static inline void u32_set(void *ptr, uint32_t val)
{
	volatile uint32_t *v = ptr;
	*v = val;
}

static inline uint32_t u32_get(void *ptr)
{
	volatile uint32_t *v = ptr;
	return *v;
}

#endif
