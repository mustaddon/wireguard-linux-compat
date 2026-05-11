#ifndef _WG_HIDDEN_H
#define _WG_HIDDEN_H

#include "device.h"

#define	ERROR_HIDDEN_LEN 0xFFFF


size_t prepare_skb_hidden(struct sk_buff *skb, struct wg_device *wg);

void skb_put_hidden_handshake(void *skb, void *buffer, struct wg_device *wg);

void skb_put_hidden_data(void *skb, void *buffer, unsigned int hlen);

unsigned int hidden_data_header_len(unsigned int len);

#endif 