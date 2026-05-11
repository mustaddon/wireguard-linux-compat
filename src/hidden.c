#include "hidden.h"
#include "messages.h"

const unsigned char hidsrc[32] = { 
    0x88, 0xab, 0xa4, 0x0d, 0xb7, 0x69, 0x42, 0x2b, 
    0xd0, 0x79, 0x2d, 0x65, 0xce, 0x69, 0x1f, 0x82, 
    0x98, 0x31, 0x89, 0xab, 0xd6, 0x5c, 0x85, 0x90, 
    0x8b, 0x90, 0x52, 0x33, 0x17, 0xff, 0x18, 0x57 };

#define HIDDEN_TYPE(val) ((val)&7)

#define HIDDEN_HEADER_LEN_RAW(val) (((val)&7) + 1)
#define HIDDEN_HEADER_LEN(val) HIDDEN_HEADER_LEN_RAW((val)>>3)

#define	SKB_XOR(skb, wg) ((((int *)(skb))[0])^(((int *)(hidsrc))[1]))
#define	SKB_XOR1(skb, xor) ((int *)(skb))[1]^=(xor);
#define	SKB_XOR2(skb, xor) ((int *)(skb))[1]^=(xor); ((int *)(skb))[2]^=(xor);
#define	SKB_XOR3(skb, xor) ((int *)(skb))[1]^=(xor); ((int *)(skb))[2]^=(xor); ((int *)(skb))[3]^=(xor);


static void xor_mac2(void *skb, size_t len, int xor)
{
    int *ptr = (int *)((u8 *)skb + len - 16);
    ptr[0] ^= xor;
    ptr[1] ^= xor;
    ptr[2] ^= xor;
    ptr[3] ^= xor;
}

size_t prepare_skb_hidden(struct sk_buff *skb, struct wg_device *wg) 
{
    int type, xor;
    size_t hlen = 0;

    if (unlikely(!pskb_may_pull(skb, 9)))
        return ERROR_HIDDEN_LEN;

    type = HIDDEN_TYPE(((u8 *)skb->data)[0]);

    if(type == 0)
    {
        hlen = HIDDEN_HEADER_LEN(((u8 *)skb->data)[0]);
        type = HIDDEN_TYPE(((u8 *)skb->data)[hlen]);
        skb_pull(skb, hlen);
    }

    xor = SKB_XOR(skb->data, wg);

    switch (type) {
        case MESSAGE_DATA:
            if (unlikely(!pskb_may_pull(skb, sizeof(struct message_data))))
                return ERROR_HIDDEN_LEN;
            SKB_XOR3(skb->data, xor);
            break;

        case MESSAGE_HANDSHAKE_INITIATION:
            if (unlikely(!pskb_may_pull(skb, sizeof(struct message_handshake_initiation))))
                return ERROR_HIDDEN_LEN;
            SKB_XOR1(skb->data, xor);
            xor_mac2(skb->data, sizeof(struct message_handshake_initiation), xor);
            break;

        case MESSAGE_HANDSHAKE_RESPONSE:
            if (unlikely(!pskb_may_pull(skb, sizeof(struct message_handshake_response))))
                return ERROR_HIDDEN_LEN;
            SKB_XOR2(skb->data, xor);
            xor_mac2(skb->data, sizeof(struct message_handshake_response), xor);
            break;

        case MESSAGE_HANDSHAKE_COOKIE:
            if (unlikely(!pskb_may_pull(skb, 8)))
                return ERROR_HIDDEN_LEN;
            SKB_XOR1(skb->data, xor);
            break;

        default:
            return ERROR_HIDDEN_LEN;
    }

    ((struct message_header *)(skb->data))->type = cpu_to_le32(type);

    return hlen;
}


static void skb_put_hidden_header(void *skb, unsigned int hlen)
{
    u8 *ptr = (u8 *)skb_push(skb, hlen);
    get_random_bytes(ptr, hlen);
    ptr[0] = (ptr[0]<<6) | ((hlen-1)<<3);
    if(ptr[0]<16) ptr[0] |= 128;
}

static void skb_add_type_noise(void *buffer)
{
    int noise = (((u8 *)buffer)[0]) | (((u32)ktime_get_coarse_boottime_ns())<<3);
    ((__le32 *)buffer)[0] = cpu_to_le32(noise);
}

void skb_put_hidden_handshake(void *skb, void *buffer, struct wg_device *wg)
{
    int xor;
    int type = ((u8 *)buffer)[0];
    skb_add_type_noise(buffer);
    xor = SKB_XOR(buffer, wg);
    
    switch (type) {
        case MESSAGE_HANDSHAKE_INITIATION:
            SKB_XOR1(buffer, xor);
            xor_mac2(buffer, sizeof(struct message_handshake_initiation), xor);
            break;

        case MESSAGE_HANDSHAKE_RESPONSE:
            SKB_XOR2(buffer, xor);
            xor_mac2(buffer, sizeof(struct message_handshake_response), xor);
            break;

        case MESSAGE_HANDSHAKE_COOKIE:
            SKB_XOR1(buffer, xor);
            break;
    }

    skb_put_hidden_header(skb, HIDDEN_HEADER_LEN_RAW((unsigned int)ktime_get_coarse_boottime_ns()));
}

unsigned int hidden_data_header_len(unsigned int len)
{
    return len != 32 ? 0 : HIDDEN_HEADER_LEN_RAW((unsigned int)ktime_get_coarse_boottime_ns());
}

void skb_put_hidden_data(void *skb, void *buffer, unsigned int hlen, struct wg_device *wg)
{
    int xor;
    skb_add_type_noise(buffer);
    xor = SKB_XOR(buffer, wg);

    //((u16 *)buffer)[1] = cpu_to_le16(wg->incoming_port);

    //((u16 *)buffer)[1] = ((u16 *)hidden_source)[0];
    
    SKB_XOR3(buffer, xor);
    if(hlen > 0) skb_put_hidden_header(skb, hlen);
}
