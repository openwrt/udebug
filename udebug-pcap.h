#ifndef __UDEBUG_PCAP_H
#define __UDEBUG_PCAP_H

#include <libubox/blobmsg.h>
#include "udebug.h"

struct pcap_context {
	uint32_t iface_id;
	void *buf;
};

struct pcap_meta {
	const char *hw, *os, *app;
};

struct pcap_interface_meta {
	const char *name;
	const char *description;
	uint8_t time_res;
	uint16_t link_type;
};

struct pcap_dbus_meta {
	const char *path, *interface, *name;
	const char *src, *dest;
};

int pcap_init(struct pcap_context *p, struct pcap_meta *meta);
int pcap_interface_init(struct pcap_context *p, uint32_t *id,
			struct pcap_interface_meta *meta);
static inline bool
pcap_interface_is_valid(struct pcap_context *p, uint32_t idx)
{
	return idx <= p->iface_id;
}

void pcap_packet_init(uint32_t iface, uint64_t timestamp);
void pcap_dbus_init_string(const struct udebug_packet_info *meta, const char *val);
void pcap_dbus_init_blob(const struct udebug_packet_info *meta, struct blob_attr *val, bool dict);
void *pcap_packet_append(const void *data, size_t len);
void pcap_packet_done(void);

int pcap_interface_rbuf_init(struct pcap_context *p, struct udebug_remote_buf *rb);
int pcap_snapshot_packet_init(struct udebug *ctx, struct udebug_iter *it);

void pcap_block_write_file(FILE *f);
void *pcap_block_get(size_t *len);

#endif
