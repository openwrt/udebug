#include <libubox/udebug.h>
#include <libubus.h>

struct udebug_ubus;
typedef void (*udebug_config_cb)(struct udebug_ubus *ctx, struct blob_attr *data, bool enabled);

struct udebug_ubus_ring {
	struct udebug_buf *buf;
	const struct udebug_buf_meta *meta;
	unsigned int size, default_size;
	unsigned int entries, default_entries;
};

struct udebug_ubus {
	struct ubus_context *ubus;
	struct uloop_timeout t;
	const char *service;
	struct ubus_subscriber sub;
	udebug_config_cb cb;
};

void udebug_netlink_msg(struct udebug_buf *buf, uint16_t proto, const void *data, size_t len);

void udebug_ubus_init(struct udebug_ubus *ctx, struct ubus_context *ubus,
		      const char *service, udebug_config_cb cb);
void udebug_ubus_ring_init(struct udebug *ud, struct udebug_ubus_ring *ring);
void udebug_ubus_apply_config(struct udebug *ud, struct udebug_ubus_ring *rings, int n,
			      struct blob_attr *data, bool enabled);
void udebug_ubus_free(struct udebug_ubus *ctx);
