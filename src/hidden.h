#ifndef _WG_HIDDEN_H
#define _WG_HIDDEN_H

#include "messages.h"

#define HIDDEN_TYPE(val) ((val)&7)
#define MSG_HIDDEN_TYPE(msg) HIDDEN_TYPE(le32_to_cpu(((struct message_header *)(msg))->type))
#define SKB_HIDDEN_TYPE(skb) MSG_HIDDEN_TYPE((skb)->data)

#define HIDDEN_HEADER_LEN(val) (1 + ((val)&3))
#define SKB_HIDDEN_HEADER_LEN(skb) HIDDEN_HEADER_LEN(((u8 *)(skb)->data)[0])

__le32 hidden_type(enum message_type type);

struct hidden_header {
	u8 val;
	u8 len;
};

struct message_hidden_header {
	u8 type;
};

void hidden_header_init(struct hidden_header *header, enum message_type type);

void skb_put_hidden_header(void *skb, struct hidden_header *header);


#endif 