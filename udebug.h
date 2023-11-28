#include <libubox/udebug.h>
#include <libubus.h>

struct udebug_ubus;
typedef void (*udebug_config_cb)(struct udebug_ubus *ctx, struct blob_attr *data, bool enabled);

struct udebug_ubus {
	struct ubus_context *ubus;
	struct uloop_timeout t;
	const char *service;
	struct ubus_subscriber sub;
	udebug_config_cb cb;
};

void udebug_ubus_init(struct udebug_ubus *ctx, struct ubus_context *ubus,
		      const char *service, udebug_config_cb cb);
void udebug_ubus_free(struct udebug_ubus *ctx);
