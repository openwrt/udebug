#ifndef __UDEBUG_SERVER_H
#define __UDEBUG_SERVER_H

#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubox/avl.h>
#include <libubox/blobmsg.h>
#include <libubox/udebug.h>
#include <libubox/udebug-proto.h>

extern int debug_level;

#define D(level, format, ...)							\
	do {									\
		if (debug_level >= level)					\
			fprintf(stderr, "DEBUG: %s(%d) " format "\n",		\
				__func__, __LINE__, ##__VA_ARGS__);		\
	} while (0)

#define DC(level, cl, format, ...)						\
	D(level, "[%s(%d)] " format, cl->proc_name, cl->pid, ##__VA_ARGS__)

struct client {
	struct list_head list;
	struct list_head bufs;
	struct uloop_fd fd;
	int notify_id;

	char proc_name[64];
	int pid;
	int uid;

	int rx_fd;
	size_t rx_ofs;
	struct {
		struct udebug_client_msg msg;
		union {
			struct blob_attr data;
			uint8_t buf[4096];
		};
	} __attribute__((packed,aligned(4))) rx_buf;
};

struct client_ring {
	struct list_head list;
	struct avl_node node;
	struct client *cl;

	int fd;
	uint32_t id;
	uint32_t ring_size, data_size;
	const char *name;
	struct blob_attr *flags;
};

extern struct avl_tree rings;

void client_alloc(int fd);
struct client_ring *client_ring_alloc(struct client *cl);
struct client_ring *client_ring_get_by_id(struct client *cl, uint32_t id);
void client_ring_free(struct client_ring *r);

static inline uint32_t ring_id(struct client_ring *r)
{
	return (uint32_t)(uintptr_t)r->node.key;
}

static inline struct client_ring *ring_get_by_id(uint32_t id)
{
	struct client_ring *r;
	void *key = (void *)(uintptr_t)id;

	return avl_find_element(&rings, key, r, node);
}

void udebug_ubus_init(void);
void udebug_ubus_ring_notify(struct client_ring *r, bool add);
void udebug_ubus_free(void);

#endif
