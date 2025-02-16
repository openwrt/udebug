#define _GNU_SOURCE
#include <math.h>
#include <libubox/utils.h>
#include <libubox/usock.h>
#include <libubox/udebug.h>
#include <ucode/module.h>
#include "udebug-pcap.h"

static uc_resource_type_t *rbuf_type, *wbuf_type, *snapshot_type, *pcap_type;
static uc_value_t *registry;
static struct udebug u;
static uc_vm_t *_vm;

struct uc_pcap {
	struct pcap_context pcap;
	int fd;
	FILE *f;
};

static size_t add_registry(uc_value_t *val)
{
	size_t i = 0;

	while (ucv_array_get(registry, i))
		i += 2;

	ucv_array_set(registry, i, ucv_get(val));

	return i;
}

static void
uc_udebug_notify_cb(struct udebug *ctx, struct udebug_remote_buf *rb)
{
	uintptr_t idx = (uintptr_t)rb->priv;
	uc_value_t *cb, *this;
	uc_vm_t *vm = _vm;

	this = ucv_array_get(registry, idx);
	cb = ucv_array_get(registry, idx + 1);

	if (!ucv_is_callable(cb))
		return;

	uc_vm_stack_push(vm, ucv_get(this));
	uc_vm_stack_push(vm, ucv_get(cb));
	if (uc_vm_call(vm, true, 0) != EXCEPTION_NONE)
		return;

	ucv_put(uc_vm_stack_pop(vm));
}

static uc_value_t *
uc_udebug_init(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *arg = uc_fn_arg(0);
	uc_value_t *flag_auto = uc_fn_arg(1);
	const char *path = NULL;

	if (ucv_type(arg) == UC_STRING)
		path = ucv_string_get(arg);

	udebug_init(&u);
	u.notify_cb = uc_udebug_notify_cb;
	if (flag_auto && !ucv_is_truish(flag_auto)) {
		if (udebug_connect(&u, path))
			return NULL;
	} else {
		udebug_auto_connect(&u, path);
	}

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_udebug_get_ring(uc_vm_t *vm, size_t nargs)
{
	struct udebug_remote_buf *rb;
	struct udebug_packet_info *info;
	uc_value_t *arg = uc_fn_arg(0);
	uc_value_t *id, *proc, *name, *pid;
	int ifname_len, ifdesc_len;
	char *ifname_buf, *ifdesc_buf;
	uc_value_t *res;
	uintptr_t idx;

#define R_IFACE_DESC	"%s:%d"

	if (ucv_type(arg) != UC_OBJECT)
		return NULL;

	id = ucv_object_get(arg, "id", NULL);
	proc = ucv_object_get(arg, "proc_name", NULL);
	name = ucv_object_get(arg, "ring_name", NULL);
	pid = ucv_object_get(arg, "pid", NULL);

	if (ucv_type(id) != UC_INTEGER ||
	    ucv_type(proc) != UC_STRING ||
	    ucv_type(name) != UC_STRING ||
	    ucv_type(pid) != UC_INTEGER)
		return NULL;

	ifname_len = strlen(ucv_string_get(name)) + 1;
	ifdesc_len = sizeof(R_IFACE_DESC) + strlen(ucv_string_get(proc)) + 10;
	rb = calloc_a(sizeof(*rb),
		      &info, sizeof(*info),
		      &ifname_buf, ifname_len,
		      &ifdesc_buf, ifdesc_len);
	rb->meta = info;

	strcpy(ifname_buf, ucv_string_get(name));
	info->attr[UDEBUG_META_IFACE_NAME] = ifname_buf;
	snprintf(ifdesc_buf, ifdesc_len, R_IFACE_DESC,
	         ucv_string_get(proc), (unsigned int)ucv_int64_get(pid));
	info->attr[UDEBUG_META_IFACE_DESC] = ifdesc_buf;

	if (udebug_remote_buf_map(&u, rb, (uint32_t)ucv_int64_get(id))) {
		free(rb);
		return NULL;
	}

	res = uc_resource_new(rbuf_type, rb);
	idx = add_registry(res);
	rb->priv = (void *)idx;

	return res;
}

static void rbuf_free(void *ptr)
{
	struct udebug_remote_buf *rb = ptr;
	uintptr_t idx;

	if (!rb)
		return;

	idx = (uintptr_t)rb->priv;
	ucv_array_set(registry, idx, NULL);
	ucv_array_set(registry, idx + 1, NULL);
	udebug_remote_buf_unmap(&u, rb);
	free(rb);
}

static uc_value_t *
uc_udebug_rbuf_fetch(uc_vm_t *vm, size_t nargs)
{
	struct udebug_remote_buf *rb = uc_fn_thisval("udebug.rbuf");
	struct udebug_snapshot *s;

	if (!rb)
		return NULL;

	s = udebug_remote_buf_snapshot(rb);
	if (!s)
		return NULL;

	return uc_resource_new(snapshot_type, s);
}

static uc_value_t *
uc_udebug_rbuf_set_poll_cb(uc_vm_t *vm, size_t nargs)
{
	struct udebug_remote_buf *rb = uc_fn_thisval("udebug.rbuf");
	uc_value_t *val = uc_fn_arg(0);
	uintptr_t idx;

	if (!rb)
		return NULL;

	idx = (uintptr_t)rb->priv;
	ucv_array_set(registry, idx + 1, ucv_get(val));
	if (!u.fd.registered)
		udebug_add_uloop(&u);
	udebug_remote_buf_set_poll(&u, rb, ucv_is_callable(val));

	return NULL;
}

static uc_value_t *
uc_udebug_rbuf_set_fetch_duration(uc_vm_t *vm, size_t nargs)
{
	struct udebug_remote_buf *rb = uc_fn_thisval("udebug.rbuf");
	uc_value_t *val = uc_fn_arg(0);
	uint64_t ts;
	double t;

	if (!rb)
		return NULL;

	t = ucv_double_get(val);
	if (isnan(t))
		return NULL;

	ts = udebug_timestamp();
	ts -= (uint64_t)(fabs(t) * UDEBUG_TS_SEC);
	udebug_remote_buf_set_start_time(rb, ts);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_udebug_rbuf_set_fetch_count(uc_vm_t *vm, size_t nargs)
{
	struct udebug_remote_buf *rb = uc_fn_thisval("udebug.rbuf");
	uc_value_t *val = uc_fn_arg(0);
	uint32_t count;

	if (!rb)
		return NULL;

	count = ucv_int64_get(val);
	udebug_remote_buf_set_start_offset(rb, count);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_udebug_rbuf_change_flags(uc_vm_t *vm, size_t nargs)
{
	struct udebug_remote_buf *rb = uc_fn_thisval("udebug.rbuf");
	uc_value_t *mask = uc_fn_arg(0);
	uc_value_t *set = uc_fn_arg(1);

	if (!rb)
		return NULL;

	if (ucv_type(mask) != UC_INTEGER || ucv_type(set) != UC_INTEGER)
		return NULL;

	udebug_remote_buf_set_flags(rb, ucv_int64_get(mask), ucv_int64_get(set));
	return ucv_boolean_new(true);
}

static uc_value_t *
uc_udebug_rbuf_get_flags(uc_vm_t *vm, size_t nargs)
{
	struct udebug_remote_buf *rb = uc_fn_thisval("udebug.rbuf");
	if (!rb)
		return NULL;

	return ucv_int64_new(udebug_buf_flags(&rb->buf));
}

static uc_value_t *
uc_udebug_rbuf_close(uc_vm_t *vm, size_t nargs)
{
	void **p = uc_fn_this("udebug.rbuf");

	if (!p)
		return NULL;

	rbuf_free(*p);
	*p = NULL;

	return NULL;
}

static void
uc_udebug_pcap_init(struct uc_pcap *p, uc_value_t *args)
{
	uc_value_t *hw, *os, *app;
	struct pcap_meta meta = {};

	if (ucv_type(args) == UC_OBJECT) {
		hw = ucv_object_get(args, "hw", NULL);
		os = ucv_object_get(args, "os", NULL);
		app = ucv_object_get(args, "app", NULL);

		meta.hw = ucv_string_get(hw);
		meta.os = ucv_string_get(os);
		meta.app = ucv_string_get(app);
	}

	pcap_init(&p->pcap, &meta);
}

static void
write_retry(int fd, const void *data, size_t len)
{
	do {
		ssize_t cur;

		cur = write(fd, data, len);
		if (cur < 0) {
			if (errno == EINTR)
				continue;

			return;
		}

		data += cur;
		len -= cur;
	} while (len > 0);
}

static void
uc_udebug_pcap_write_block(struct uc_pcap *p)
{
	size_t len;
	void *data;

	data = pcap_block_get(&len);
	write_retry(p->fd, data, len);
}

static uc_value_t *
uc_debug_pcap_init(int fd, uc_value_t *args)
{
	struct uc_pcap *p;

	if (fd < 0)
		return NULL;

	p = calloc(1, sizeof(*p));
	p->fd = fd;
	uc_udebug_pcap_init(p, args);
	uc_udebug_pcap_write_block(p);

	return uc_resource_new(pcap_type, p);
}

static uc_value_t *
uc_udebug_pcap_file(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *file = uc_fn_arg(0);
	uc_value_t *args = uc_fn_arg(1);
	int fd = -1;

	if (ucv_type(file) == UC_STRING) {
		fd = open(ucv_string_get(file), O_WRONLY | O_CREAT, 0644);
		if (ftruncate(fd, 0) < 0) {
			close(fd);
			return NULL;
		}
	} else if (!file)
		fd = STDOUT_FILENO;

	return uc_debug_pcap_init(fd, args);
}

static uc_value_t *
uc_udebug_pcap_udp(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *host = uc_fn_arg(0);
	uc_value_t *port = uc_fn_arg(1);
	uc_value_t *args = uc_fn_arg(2);
	const char *port_str;
	int fd = -1;

	if (ucv_type(host) != UC_STRING)
		return NULL;

	if (ucv_type(port) == UC_STRING)
		port_str = ucv_string_get(port);
	else if (ucv_type(port) == UC_INTEGER)
		port_str = usock_port(ucv_int64_get(port));
	else
		return NULL;

	fd = usock(USOCK_UDP, ucv_string_get(host), port_str);

	return uc_debug_pcap_init(fd, args);
}

static struct udebug_snapshot *
uc_get_snapshot(uc_value_t *val)
{
	return ucv_resource_data(val, "udebug.snapshot");
}

static uc_value_t *
uc_udebug_pcap_write(uc_vm_t *vm, size_t nargs)
{
	struct uc_pcap *p = uc_fn_thisval("udebug.pcap");
	uc_value_t *arg = uc_fn_arg(0);
	size_t n = ucv_type(arg) == UC_ARRAY ? ucv_array_length(arg) : 1;
	struct udebug_snapshot **s;
	struct udebug_iter it;

	if (!p)
		return NULL;

	s = alloca(n * sizeof(*s));
	if (ucv_type(arg) == UC_ARRAY)
		for (size_t i = 0; i < n; i++) {
			if ((s[i] = uc_get_snapshot(ucv_array_get(arg, i))) == NULL)
				return NULL;
	} else {
		if ((s[0] = uc_get_snapshot(arg)) == NULL)
			return NULL;
	}

	udebug_iter_start(&it, s, n);
	while (udebug_iter_next(&it)) {
		struct udebug_remote_buf *rb;

		rb = udebug_remote_buf_get(&u, it.s->rbuf_idx);
		if (!pcap_interface_is_valid(&p->pcap, rb->pcap_iface)) {
			if (pcap_interface_rbuf_init(&p->pcap, rb))
				continue;

			uc_udebug_pcap_write_block(p);
		}

		if (pcap_snapshot_packet_init(&u, &it))
			continue;

		uc_udebug_pcap_write_block(p);
	}

	return NULL;
}

static void
uc_udebug_pcap_free(void *ptr)
{
	struct uc_pcap *p = ptr;

	if (!p)
		return;

	if (p->fd >= 0)
		close(p->fd);
	free(p);
}

static uc_value_t *
uc_udebug_pcap_close(uc_vm_t *vm, size_t nargs)
{
	void **p = uc_fn_this("udebug.pcap");

	if (!p)
		return NULL;

	uc_udebug_pcap_free(*p);
	*p = NULL;

	return NULL;
}

static uc_value_t *
uc_udebug_snapshot_get_ring(uc_vm_t *vm, size_t nargs)
{
	struct udebug_snapshot *s = uc_fn_thisval("udebug.snapshot");
	struct udebug_remote_buf *rb;
	uintptr_t idx;

	if (!s)
		return NULL;

	rb = udebug_remote_buf_get(&u, s->rbuf_idx);
	if (!rb)
		return NULL;

	idx = (uintptr_t)rb->priv;
	return ucv_array_get(registry, idx);
}

static uc_value_t *
uc_udebug_foreach_packet(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *arg = uc_fn_arg(0);
	uc_value_t *fn = uc_fn_arg(1);
	size_t n = ucv_type(arg) == UC_ARRAY ? ucv_array_length(arg) : 1;
	struct udebug_snapshot **s;
	struct udebug_iter it;

	if (!ucv_is_callable(fn))
		return NULL;

	s = alloca(n * sizeof(*s));
	if (ucv_type(arg) == UC_ARRAY)
		for (size_t i = 0; i < n; i++) {
			if ((s[i] = uc_get_snapshot(ucv_array_get(arg, i))) == NULL)
				return NULL;
	} else {
		if ((s[0] = uc_get_snapshot(arg)) == NULL)
			return NULL;
	}

	udebug_iter_start(&it, s, n);
	while (udebug_iter_next(&it)) {
		uc_value_t *s_obj;

		if (ucv_type(arg) == UC_ARRAY)
			s_obj = ucv_array_get(arg, it.s_idx);
		else
			s_obj = arg;

		uc_vm_stack_push(vm, ucv_get(_uc_fn_this_res(vm)));
		uc_vm_stack_push(vm, ucv_get(fn));
		uc_vm_stack_push(vm, ucv_get(s_obj));
		uc_vm_stack_push(vm, ucv_string_new_length(it.data, it.len));

		if (uc_vm_call(vm, true, 2) != EXCEPTION_NONE)
			break;

		ucv_put(uc_vm_stack_pop(vm));
	}

	return NULL;
}

static uc_value_t *
uc_udebug_create_ring(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *name, *flags_arr, *size, *entries;
	uc_value_t *meta_obj = uc_fn_arg(0);
	struct udebug_buf_flag *flags;
	struct udebug_buf_meta *meta;
	struct udebug_buf *buf;
	size_t flag_str_len = 0;
	size_t flags_len = 0;
	char *name_buf, *flag_name_buf;

	if (ucv_type(meta_obj) != UC_OBJECT)
		return NULL;

	name = ucv_object_get(meta_obj, "name", NULL);
	flags_arr = ucv_object_get(meta_obj, "flags", NULL);
	size = ucv_object_get(meta_obj, "size", NULL);
	entries = ucv_object_get(meta_obj, "entries", NULL);

	if (ucv_type(name) != UC_STRING ||
	    ucv_type(size) != UC_INTEGER || ucv_type(entries) != UC_INTEGER)
		return NULL;

	if (ucv_type(flags_arr) == UC_ARRAY) {
		flags_len = ucv_array_length(flags_arr);
		for (size_t i = 0; i < flags_len; i++) {
			uc_value_t *f = ucv_array_get(flags_arr, i);
			if (ucv_type(f) != UC_STRING)
				return NULL;
			flag_str_len += strlen(ucv_string_get(f)) + 1;
		}
	}

	buf = calloc_a(sizeof(*buf),
		       &name_buf, strlen(ucv_string_get(name)) + 1,
		       &meta, sizeof(meta),
		       &flags, flags_len * sizeof(*flags),
		       &flag_name_buf, flag_str_len);
	meta->name = strcpy(name_buf, ucv_string_get(name));
	meta->format = UDEBUG_FORMAT_STRING;
	meta->flags = flags;

	for (size_t i = 0; i < flags_len; i++) {
		uc_value_t *f = ucv_array_get(flags_arr, i);
		const char *str = ucv_string_get(f);
		size_t len = strlen(str) + 1;

		flags->name = memcpy(name_buf, str, len);
		flags->mask = 1ULL << i;
		name_buf += len;
		meta->n_flags++;
	}

	if (udebug_buf_init(buf, ucv_int64_get(size), ucv_int64_get(entries))) {
		free(buf);
		return NULL;
	}

	udebug_buf_add(&u, buf, meta);

	return uc_resource_new(wbuf_type, buf);
}

static void wbuf_free(void *ptr)
{
	if (!ptr)
		return;

	udebug_buf_free(ptr);
	free(ptr);
}

static uc_value_t *
uc_udebug_wbuf_flags(uc_vm_t *vm, size_t nargs)
{
	struct udebug_buf *buf = uc_fn_thisval("udebug.wbuf");

	if (!buf)
		return NULL;

	return ucv_int64_new(udebug_buf_flags(buf));
}

static uc_value_t *
uc_udebug_wbuf_close(uc_vm_t *vm, size_t nargs)
{
	void **p = uc_fn_this("udebug.wbuf");

	if (!p)
		return NULL;

	wbuf_free(*p);
	*p = NULL;

	return NULL;
}

static void
uc_udebug_wbuf_add_string(struct udebug_buf *buf, uc_value_t *val)
{
	udebug_entry_init(buf);
	udebug_entry_append(buf, ucv_string_get(val), ucv_string_length(val));
	udebug_entry_add(buf);
}

static uc_value_t *
uc_udebug_wbuf_add(uc_vm_t *vm, size_t nargs)
{
	struct udebug_buf *buf = uc_fn_thisval("udebug.wbuf");
	uc_value_t *arg = uc_fn_arg(0);

	if (!buf || ucv_type(arg) != UC_STRING)
		return NULL;

	uc_udebug_wbuf_add_string(buf, arg);

	return ucv_boolean_new(true);
}

static const uc_function_list_t pcap_fns[] = {
	{ "close", uc_udebug_pcap_close },
	{ "write", uc_udebug_pcap_write },
};

static const uc_function_list_t snapshot_fns[] = {
	{ "get_ring", uc_udebug_snapshot_get_ring }
};

static const uc_function_list_t wbuf_fns[] = {
	{ "add", uc_udebug_wbuf_add },
	{ "flags", uc_udebug_wbuf_flags },
	{ "close", uc_udebug_wbuf_close },
};

static const uc_function_list_t rbuf_fns[] = {
	{ "set_poll_cb", uc_udebug_rbuf_set_poll_cb },
	{ "fetch", uc_udebug_rbuf_fetch },
	{ "change_flags", uc_udebug_rbuf_change_flags },
	{ "get_flags", uc_udebug_rbuf_get_flags },
	{ "set_fetch_duration", uc_udebug_rbuf_set_fetch_duration },
	{ "set_fetch_count", uc_udebug_rbuf_set_fetch_count },
	{ "close", uc_udebug_rbuf_close },
};

static const uc_function_list_t global_fns[] = {
	{ "init", uc_udebug_init },
	{ "create_ring", uc_udebug_create_ring },
	{ "get_ring", uc_udebug_get_ring },
	{ "pcap_file", uc_udebug_pcap_file },
	{ "pcap_udp", uc_udebug_pcap_udp },
	{ "foreach_packet", uc_udebug_foreach_packet },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	_vm = vm;
	uc_function_list_register(scope, global_fns);

	wbuf_type = uc_type_declare(vm, "udebug.wbuf", wbuf_fns, wbuf_free);
	rbuf_type = uc_type_declare(vm, "udebug.rbuf", rbuf_fns, rbuf_free);
	snapshot_type = uc_type_declare(vm, "udebug.snapshot", snapshot_fns, free);
	pcap_type = uc_type_declare(vm, "udebug.pcap", pcap_fns, uc_udebug_pcap_free);

	registry = ucv_array_new(vm);
	uc_vm_registry_set(vm, "udebug.registry", registry);
}
