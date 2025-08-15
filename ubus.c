#include <fnmatch.h>
#include <libubus.h>
#include "server.h"

struct ubus_auto_conn conn;
struct blob_buf b;
static struct ubus_object udebug_object;
static struct blob_attr *service_config;
static struct blob_attr *service_config_override;

enum {
	LIST_ATTR_PROCNAME,
	LIST_ATTR_RINGNAME,
	LIST_ATTR_PID,
	LIST_ATTR_UID,
	__LIST_ATTR_MAX,
};

static const struct blobmsg_policy list_policy[__LIST_ATTR_MAX] = {
	[LIST_ATTR_PROCNAME] = { "proc_name", BLOBMSG_TYPE_ARRAY },
	[LIST_ATTR_RINGNAME] = { "ring_name", BLOBMSG_TYPE_ARRAY },
	[LIST_ATTR_PID] = { "pid", BLOBMSG_TYPE_ARRAY },
	[LIST_ATTR_UID] = { "uid", BLOBMSG_TYPE_ARRAY },
};

static bool
string_array_match(const char *val, struct blob_attr *match)
{
	struct blob_attr *cur;
	int rem;

	if (!match || !blobmsg_len(match))
		return true;

	if (blobmsg_check_array(match, BLOBMSG_TYPE_STRING) < 0)
		return false;

	blobmsg_for_each_attr(cur, match, rem) {
		if (fnmatch(blobmsg_get_string(cur), val, 0) == 0)
			return true;
	}

	return false;
}

static bool
int_array_match(unsigned int val, struct blob_attr *match)
{
	struct blob_attr *cur;
	int rem;

	if (!match || !blobmsg_len(match))
		return true;

	if (blobmsg_check_array(match, BLOBMSG_TYPE_INT32) < 0)
		return false;

	blobmsg_for_each_attr(cur, match, rem) {
		if (val == blobmsg_get_u32(cur))
			return true;
	}

	return false;
}

static bool
udebug_list_match(struct client_ring *r, struct blob_attr **tb)
{
	return string_array_match(r->cl->proc_name, tb[LIST_ATTR_PROCNAME]) &&
	       string_array_match(r->name, tb[LIST_ATTR_RINGNAME]) &&
	       int_array_match(r->cl->pid, tb[LIST_ATTR_PID]) &&
	       int_array_match(r->cl->uid, tb[LIST_ATTR_UID]);
}

static void
udebug_list_add_ring_data(struct client_ring *r)
{
	blobmsg_add_u32(&b, "id", ring_id(r));
	blobmsg_add_string(&b, "proc_name", r->cl->proc_name);
	blobmsg_add_string(&b, "ring_name", r->name);
	blobmsg_add_u32(&b, "pid", r->cl->pid);
	blobmsg_add_u32(&b, "uid", r->cl->uid);
	blobmsg_add_u32(&b, "ring_size", r->ring_size);
	blobmsg_add_u32(&b, "data_size", r->data_size);
	if (r->flags)
		blobmsg_add_blob(&b, r->flags);
}

void udebug_ubus_ring_notify(struct client_ring *r, bool add)
{
	blob_buf_init(&b, 0);
	udebug_list_add_ring_data(r);
	ubus_notify(&conn.ctx, &udebug_object, add ? "add" : "remove", b.head, -1);
}

static void
udebug_list_add_ring(struct client_ring *r)
{
	void *c;

	c = blobmsg_open_table(&b, NULL);
	udebug_list_add_ring_data(r);
	blobmsg_close_table(&b, c);
}

static int
udebug_list(struct ubus_context *ctx, struct ubus_object *obj,
	    struct ubus_request_data *req, const char *method,
	    struct blob_attr *msg)
{
	struct blob_attr *tb[__LIST_ATTR_MAX];
	struct client_ring *r;
	void *c;

	blobmsg_parse_attr(list_policy, __LIST_ATTR_MAX, tb, msg);

	blob_buf_init(&b, 0);
	c = blobmsg_open_array(&b, "results");
	avl_for_each_element(&rings, r, node)
		if (udebug_list_match(r, tb))
			udebug_list_add_ring(r);
	blobmsg_close_array(&b, c);
	ubus_send_reply(ctx, req, b.head);

	return 0;
}

enum {
	CFG_ATTR_OVERRIDE,
	CFG_ATTR_SERVICE,
	__CFG_ATTR_MAX
};
static const struct blobmsg_policy config_policy[__CFG_ATTR_MAX] = {
	[CFG_ATTR_OVERRIDE] = { "override", BLOBMSG_TYPE_BOOL },
	[CFG_ATTR_SERVICE] = { "service", BLOBMSG_TYPE_TABLE },
};

static struct blob_attr *
udebug_fill_config(int override)
{
	struct blob_attr *config;

	if (override < 0)
		config = service_config_override ? : service_config;
	else if (override)
		config = service_config_override;
	else
		config = service_config;

	blob_buf_init(&b, 0);
	if (config)
		blobmsg_add_blob(&b, config);
	else
		blobmsg_close_table(&b, blobmsg_open_table(&b, "service"));

	return b.head;
}

static int
udebug_set_config(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__CFG_ATTR_MAX], *cur;
	struct blob_attr **dest = &service_config;

	blobmsg_parse_attr(config_policy, __CFG_ATTR_MAX, tb, msg);
	if ((cur = tb[CFG_ATTR_OVERRIDE]) != NULL &&
	    blobmsg_get_bool(cur))
		dest = &service_config_override;

	if ((cur = tb[CFG_ATTR_SERVICE]) != NULL) {
		free(*dest);
		*dest = blob_memdup(cur);
	} else if (dest == &service_config_override) {
		free(*dest);
		*dest = NULL;
	}

	if (dest != &service_config || !service_config_override)
		ubus_notify(ctx, obj, "config", udebug_fill_config(-1), -1);

	return 0;
}

static int
udebug_get_config(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__CFG_ATTR_MAX], *cur;
	int override = -1;

	blobmsg_parse_attr(config_policy, __CFG_ATTR_MAX, tb, msg);
	if ((cur = tb[CFG_ATTR_OVERRIDE]) != NULL)
		override = blobmsg_get_bool(cur);

	ubus_send_reply(ctx, req, udebug_fill_config(override));

	return 0;
}

static const struct ubus_method udebug_methods[] = {
	UBUS_METHOD("list", udebug_list, list_policy),
	UBUS_METHOD("set_config", udebug_set_config, config_policy),
	UBUS_METHOD_MASK("get_config", udebug_get_config, config_policy,
			 1 << CFG_ATTR_OVERRIDE),
};

static struct ubus_object_type udebug_object_type =
	UBUS_OBJECT_TYPE("udebug", udebug_methods);

static struct ubus_object udebug_object = {
	.name = "udebug",
	.type = &udebug_object_type,
	.methods = udebug_methods,
	.n_methods = ARRAY_SIZE(udebug_methods),
};

static void ubus_connect_cb(struct ubus_context *ctx)
{
	ubus_add_object(ctx, &udebug_object);
}

void udebug_ubus_init(void)
{
	conn.cb = ubus_connect_cb;
	ubus_auto_connect(&conn);
}

void udebug_ubus_free(void)
{
	ubus_auto_shutdown(&conn);
}
