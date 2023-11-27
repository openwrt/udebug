#include "server.h"

static FILE *urandom;

AVL_TREE(rings, udebug_id_cmp, true, NULL);

struct client_ring *client_ring_get_by_id(struct client *cl, uint32_t id)
{
	struct client_ring *r;

	list_for_each_entry(r, &cl->bufs, list)
		if (r->id == id)
			return r;

	return NULL;
}

static uint32_t gen_ring_id(void)
{
	uint32_t val = 0;

	if (!urandom && (urandom = fopen("/dev/urandom", "r")) == NULL)
		return 0;

	if (fread(&val, sizeof(val), 1, urandom) != 1)
		return 0;

	return val;
}

struct client_ring *client_ring_alloc(struct client *cl)
{
	enum {
		RING_ATTR_NAME,
		RING_ATTR_FLAGS,
		__RING_ATTR_MAX,
	};
	static const struct blobmsg_policy policy[__RING_ATTR_MAX] = {
		[RING_ATTR_NAME] = { "name", BLOBMSG_TYPE_STRING },
		[RING_ATTR_FLAGS] = { "flags", BLOBMSG_TYPE_ARRAY },
	};
	struct udebug_client_msg *msg = &cl->rx_buf.msg;
	struct blob_attr *tb[__RING_ATTR_MAX], *meta;
	struct client_ring *r;
	size_t meta_len;

	if (cl->rx_fd < 0)
		return NULL;

	meta_len = blob_pad_len(&cl->rx_buf.data);
	r = calloc_a(sizeof(*r), &meta, meta_len);
	memcpy(meta, cl->rx_buf.buf, meta_len);

	blobmsg_parse_attr(policy, __RING_ATTR_MAX, tb, meta);
	if (!tb[RING_ATTR_NAME]) {
		close(cl->rx_fd);
		free(r);
		return NULL;
	}

	r->name = blobmsg_get_string(tb[RING_ATTR_NAME]);
	r->flags = tb[RING_ATTR_FLAGS];

	r->cl = cl;
	r->id = msg->id;
	r->fd = cl->rx_fd;
	cl->rx_fd = -1;
	r->ring_size = msg->ring_size;
	r->data_size = msg->data_size;
	list_add_tail(&r->list, &cl->bufs);

	r->node.key = (void *)(uintptr_t)gen_ring_id();
	avl_insert(&rings, &r->node);
	udebug_ubus_ring_notify(r, true);
	DC(2, cl, "add ring %d [%x] ring_size=%x data_size=%x", r->id, ring_id(r), r->ring_size, r->data_size);

	return r;
}

void client_ring_free(struct client_ring *r)
{
	DC(2, r->cl, "free ring %d [%x]", r->id, ring_id(r));
	udebug_ubus_ring_notify(r, false);
	avl_delete(&rings, &r->node);
	list_del(&r->list);
	close(r->fd);
	free(r);
}
