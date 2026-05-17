#ifndef _WG_HIDDEN_H
#define _WG_HIDDEN_H

#include "device.h"

#define	ERROR_HIDDEN_LEN 0xFFFF


size_t prepare_skb_hidden(struct sk_buff *skb, struct wg_device *wg);

void skb_put_hidden_handshake(void *skb, void *buffer, struct wg_device *wg);

void skb_put_hidden_data(void *skb, void *buffer, unsigned int hlen, struct wg_device *wg);

unsigned int hidden_data_header_len(unsigned int len);


struct QUIC_message_init {
	u8 flags;
	__be32 version;
	u8 DCID_len;
	u64 DCID;
	u8 SCID_len;
	u8 SCID[3];
	u8 token_len;
	__be16 data_len;
} __attribute__((packed));

struct QUIC_message_resp {
	u8 flags;
	__be32 version;
	u8 DCID_len;
	u8 DCID[3];
	u8 SCID_len;
	u8 SCID[3];
	u8 token_len;
	__be16 data_len;
} __attribute__((packed));

struct QUIC_message_cook {
	u8 flags;
	__be32 version;
	u8 DCID_len;
	u8 DCID[3];
	u8 SCID_len;
	u8 token_len;
	__be16 data_len;
} __attribute__((packed));

#endif 