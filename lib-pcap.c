#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <libubox/utils.h>
#include <libubox/blobmsg.h>
#include <libubox/udebug.h>
#include <libubox/udebug-proto.h>
#include "udebug-pcap.h"

static char pcap_buf[65536];
static struct pcap_block_hdr *pcap_hdr = (struct pcap_block_hdr *)pcap_buf;

struct pcap_block_hdr {
	uint32_t type;
	uint32_t len;
};

struct pcap_shb_hdr {
	uint32_t endian;
	uint16_t major;
	uint16_t minor;
	uint64_t section_len;
};

struct pcap_idb_hdr {
	uint16_t link_type;
	uint16_t _pad;
	uint32_t snap_len;
};

struct pcap_epb_hdr {
	uint32_t iface;
	uint32_t ts_hi;
	uint32_t ts_lo;
	uint32_t cap_len;
	uint32_t pkt_len;
};

struct pcap_opt_hdr {
	uint16_t id;
	uint16_t len;
};

#define PCAPNG_BTYPE_SHB	0x0a0d0d0a
#define PCAPNG_BTYPE_IDB	1
#define PCAPNG_BTYPE_EPB	6

#define PCAPNG_ENDIAN		0x1a2b3c4d

static void *
pcap_block_start(uint32_t type, uint32_t len)
{
	struct pcap_block_hdr *b = pcap_hdr;

	b->type = type;
	b->len = len + sizeof(*b);
	memset(b + 1, 0, len);

	return b + 1;
}

static void *
pcap_block_append(int len)
{
	struct pcap_block_hdr *b = pcap_hdr;
	void *data = &pcap_buf[b->len];

	memset(data, 0, len);
	b->len += len;

	return data;
}

static void *
pcap_opt_append(int id, int len)
{
	struct pcap_opt_hdr *opt;

	len = (len + 3) & ~3;
	opt = pcap_block_append(sizeof(*opt) + len);
	opt->id = id;
	opt->len = len;

	return opt + 1;
}

static void
pcap_opt_str_add(int id, const char *val)
{
	int len;

	if (!val)
		 return;

	len = strlen(val) + 1;
	memcpy(pcap_opt_append(id, len), val, len);
}

static void
pcap_opt_u8_add(uint16_t id, uint8_t val)
{
	*(uint8_t *)pcap_opt_append(id, 1) = val;
}

static void
pcap_opt_end(void)
{
	pcap_block_append(4);
}

static uint32_t __pcap_block_align(int offset, int val)
{
	struct pcap_block_hdr *b = pcap_hdr;
	uint32_t cur_len = b->len - offset;
	uint32_t aligned_len = (cur_len + (val - 1)) & ~(val - 1);
	uint32_t pad = aligned_len - cur_len;

	if (pad)
		pcap_block_append(pad);

	return pad;
}

static uint32_t pcap_block_align(int val)
{
	return __pcap_block_align(0, val);
}

static int
pcap_block_end(void)
{
	struct pcap_block_hdr *b = (struct pcap_block_hdr *)pcap_buf;
	uint32_t *len;

	pcap_block_align(4);
	len = (uint32_t *)&pcap_buf[b->len];
	b->len += 4;
	*len = b->len;

	return *len;
}


int pcap_init(struct pcap_context *p, struct pcap_meta *meta)
{
	struct pcap_shb_hdr *shb;

	shb = pcap_block_start(PCAPNG_BTYPE_SHB, sizeof(*shb));
	shb->endian = PCAPNG_ENDIAN;
	shb->major = 1;
	shb->section_len = ~0ULL;
	pcap_opt_str_add(2, meta->hw);
	pcap_opt_str_add(3, meta->os);
	pcap_opt_str_add(4, meta->app);
	pcap_opt_end();
	pcap_block_end();

	return 0;
}

int pcap_interface_init(struct pcap_context *p, uint32_t *id,
			struct pcap_interface_meta *meta)
{
	struct pcap_idb_hdr *idb;

	*id = p->iface_id++;
	idb = pcap_block_start(PCAPNG_BTYPE_IDB, sizeof(*idb));
	idb->link_type = meta->link_type;
	idb->snap_len = 0xffff;
	pcap_opt_str_add(2, meta->name);
	pcap_opt_str_add(3, meta->description);
	pcap_opt_u8_add(9, meta->time_res);
	pcap_opt_end();
	pcap_block_end();

	return 0;
}

void pcap_packet_init(uint32_t iface, uint64_t ts)
{
	struct pcap_epb_hdr *epb;

	epb = pcap_block_start(PCAPNG_BTYPE_EPB, sizeof(*epb));
	epb->iface = iface;
	epb->ts_hi = ts >> 32;
	epb->ts_lo = (uint32_t)ts;
}

void *pcap_packet_append(const void *data, size_t len)
{
	void *buf;

	buf = pcap_block_append(len);
	if (data)
		memcpy(buf, data, len);

	return buf;
}

void pcap_packet_done(void)
{
	struct pcap_epb_hdr *epb = (struct pcap_epb_hdr *)&pcap_hdr[1];
	unsigned int len;

	len = pcap_hdr->len - sizeof(*pcap_hdr) - sizeof(*epb);
	epb->cap_len = epb->pkt_len = len;
	pcap_block_align(4);
	pcap_block_end();
}

int pcap_interface_rbuf_init(struct pcap_context *p, struct udebug_remote_buf *rb)
{
	const struct udebug_packet_info *meta = rb->meta;
	struct pcap_interface_meta if_meta = {
		.time_res = 6,
		.name = meta->attr[UDEBUG_META_IFACE_NAME],
		.description = meta->attr[UDEBUG_META_IFACE_DESC],
	};

	if (rb->buf.hdr->format == UDEBUG_FORMAT_PACKET)
		if_meta.link_type = rb->buf.hdr->sub_format;
	else if (rb->buf.hdr->format == UDEBUG_FORMAT_STRING)
		if_meta.link_type = 147;

	return pcap_interface_init(p, &rb->pcap_iface, &if_meta);
}

int pcap_snapshot_packet_init(struct udebug *ctx, struct udebug_iter *it)
{
	struct udebug_remote_buf *rb;
	struct udebug_snapshot *s = it->s;

	rb = udebug_remote_buf_get(ctx, s->rbuf_idx);
	if (!rb)
		return -1;

	pcap_packet_init(rb->pcap_iface, it->timestamp);

	switch (s->format) {
	case UDEBUG_FORMAT_PACKET:
	case UDEBUG_FORMAT_STRING:
		pcap_packet_append(it->data, it->len);
		break;
	case UDEBUG_FORMAT_BLOBMSG:
		break;
	default:
		return -1;
	}

	pcap_packet_done();

	return 0;
}

bool pcap_block_write_file(FILE *f)
{
	if (fwrite(pcap_buf, pcap_hdr->len, 1, f) != 1)
		return false;

	fflush(f);
	return true;
}

void *pcap_block_get(size_t *len)
{
	*len = pcap_hdr->len;

	return pcap_buf;
}
