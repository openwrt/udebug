#include "udebug.h"

static struct blob_attr *
find_attr(struct blob_attr *attr, const char *name, enum blobmsg_type type)
{
	struct blobmsg_policy policy = { name, type };
	struct blob_attr *ret;

	if (!attr)
		return NULL;

	blobmsg_parse_attr(&policy, 1, &ret, attr);
	return ret;
}

static void
udebug_ubus_msg_cb(struct udebug_ubus *ctx, struct blob_attr *data)
{
	struct blob_attr *en_attr;
	bool enabled;

	data = find_attr(data, "service", BLOBMSG_TYPE_TABLE);
	data = find_attr(data, ctx->service, BLOBMSG_TYPE_TABLE);
	if (!data)
		return;

	en_attr = find_attr(data, "enabled", BLOBMSG_TYPE_STRING);
	enabled = en_attr && !!atoi(blobmsg_get_string(en_attr));
	ctx->cb(ctx, data, enabled);
}

static int
udebug_ubus_notify_cb(struct ubus_context *ubus, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct udebug_ubus *ctx = container_of(obj, struct udebug_ubus, sub.obj);

	if (!strcmp(method, "config"))
		udebug_ubus_msg_cb(ctx, msg);

	return 0;
}

static void
udebug_ubus_req_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	udebug_ubus_msg_cb(req->priv, msg);
}

static bool
udebug_ubus_new_obj_cb(struct ubus_context *ubus, struct ubus_subscriber *sub,
		       const char *path)
{
	struct udebug_ubus *ctx = container_of(sub, struct udebug_ubus, sub);

	if (strcmp(path, "udebug") != 0)
		return false;

	uloop_timeout_set(&ctx->t, 1);
	return true;
}

static void udebug_ubus_get_config(struct uloop_timeout *t)
{
	struct udebug_ubus *ctx = container_of(t, struct udebug_ubus, t);
	uint32_t id;

	if (ubus_lookup_id(ctx->ubus, "udebug", &id))
		return;

	ubus_invoke(ctx->ubus, id, "get_config", NULL, udebug_ubus_req_cb, ctx, 1000);
}

void udebug_ubus_ring_init(struct udebug *ud, struct udebug_ubus_ring *ring)
{
	if (!ring->size)
		ring->size = ring->default_size;
	if (!ring->entries)
		ring->entries = ring->default_entries;
	udebug_buf_init(ring->buf, ring->entries, ring->size);
	udebug_buf_add(ud, ring->buf, ring->meta);
}

void udebug_ubus_apply_config(struct udebug *ud, struct udebug_ubus_ring *rings, int n,
			      struct blob_attr *data, bool enabled)
{
	enum {
		CFG_ATTR_ENABLE,
		CFG_ATTR_SIZE,
		CFG_ATTR_ENTRIES,
		__CFG_ATTR_MAX,
	};
	static struct blobmsg_policy policy[] = {
		[CFG_ATTR_ENABLE] = { NULL, BLOBMSG_TYPE_STRING },
		[CFG_ATTR_SIZE] = { NULL, BLOBMSG_TYPE_STRING },
		[CFG_ATTR_ENTRIES] = { NULL, BLOBMSG_TYPE_STRING },
	};

	for (size_t i = 0; i < n; i++) {
		struct blob_attr *tb[__CFG_ATTR_MAX], *cur;
		struct udebug_buf *buf = rings[i].buf;
		const char *name = rings[i].meta->name;
		int name_len = strlen(name);
		unsigned int size, entries;
		bool cur_enabled = enabled;
		char *str;

		policy[CFG_ATTR_ENABLE].name = name;

#define SIZE_FMT "%s_size"
		str = alloca(sizeof(SIZE_FMT) + name_len);
		sprintf(str, SIZE_FMT, name);
		policy[CFG_ATTR_SIZE].name = str;

#define ENTRIES_FMT "%s_entries"
		str = alloca(sizeof(ENTRIES_FMT) + name_len);
		sprintf(str, ENTRIES_FMT, name);
		policy[CFG_ATTR_ENTRIES].name = str;

		blobmsg_parse_attr(policy, __CFG_ATTR_MAX, tb, data);

		if ((cur = tb[CFG_ATTR_ENABLE]) != NULL)
			cur_enabled = !!atoi(blobmsg_get_string(cur));

		if ((cur = tb[CFG_ATTR_SIZE]) != NULL)
			size = atoi(blobmsg_get_string(cur));
		else
			size = rings[i].default_size;

		if ((cur = tb[CFG_ATTR_ENTRIES]) != NULL)
			entries = atoi(blobmsg_get_string(cur));
		else
			entries = rings[i].default_entries;

		if (udebug_buf_valid(buf) == cur_enabled &&
		    size == rings[i].size &&
		    entries == rings[i].entries)
			continue;

		if (udebug_buf_valid(buf))
			udebug_buf_free(buf);

		rings[i].size = size;
		rings[i].entries = entries;
		if (!cur_enabled)
			continue;

		udebug_ubus_ring_init(ud, &rings[i]);
	}
}

void udebug_ubus_init(struct udebug_ubus *ctx, struct ubus_context *ubus,
		      const char *service, udebug_config_cb cb)
{
	ctx->ubus = ubus;
	ctx->service = service;
	ctx->cb = cb;
	ctx->sub.new_obj_cb = udebug_ubus_new_obj_cb;
	ctx->sub.cb = udebug_ubus_notify_cb;
	ubus_register_subscriber(ubus, &ctx->sub);

	ctx->t.cb = udebug_ubus_get_config;
}

void udebug_ubus_free(struct udebug_ubus *ctx)
{
	if (!ctx->ubus)
		return;

	uloop_timeout_cancel(&ctx->t);
	ubus_unregister_subscriber(ctx->ubus, &ctx->sub);
}
