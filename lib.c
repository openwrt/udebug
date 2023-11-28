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
