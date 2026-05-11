#include "hidden.h"
#include "messages.h"

#define HIDDEN_TYPE(val) ((val)&7)

#define HIDDEN_HEADER_LEN_RAW(val) (((val)&7) + 1)
#define HIDDEN_HEADER_LEN(val) HIDDEN_HEADER_LEN_RAW((val)>>3)

#define	HIDDEN_XOR 0x8cb51d5e

#define	SKB_XOR1(skb, xor) ((int *)(skb))[1]^=xor;
#define	SKB_XOR2(skb, xor) ((int *)(skb))[1]^=xor; ((int *)(skb))[2]^=xor;
#define	SKB_XOR3(skb, xor) ((int *)(skb))[1]^=xor; ((int *)(skb))[2]^=xor; ((int *)(skb))[3]^=xor;


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
    int type;
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

    switch (type) {
        case MESSAGE_DATA:
            if (unlikely(!pskb_may_pull(skb, 16)))
                return ERROR_HIDDEN_LEN;
            SKB_XOR3(skb->data, HIDDEN_XOR);
            break;

        case MESSAGE_HANDSHAKE_INITIATION:
            if (unlikely(!pskb_may_pull(skb, sizeof(struct message_handshake_initiation))))
                return ERROR_HIDDEN_LEN;
            SKB_XOR1(skb->data, HIDDEN_XOR);
            xor_mac2(skb->data, sizeof(struct message_handshake_initiation), HIDDEN_XOR);
            break;

        case MESSAGE_HANDSHAKE_RESPONSE:
            if (unlikely(!pskb_may_pull(skb, sizeof(struct message_handshake_response))))
                return ERROR_HIDDEN_LEN;
            SKB_XOR2(skb->data, HIDDEN_XOR);
            xor_mac2(skb->data, sizeof(struct message_handshake_response), HIDDEN_XOR);
            break;

        case MESSAGE_HANDSHAKE_COOKIE:
            if (unlikely(!pskb_may_pull(skb, 8)))
                return ERROR_HIDDEN_LEN;
            SKB_XOR1(skb->data, HIDDEN_XOR);
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

void skb_put_hidden_handshake(void *skb, void *buffer, struct wg_device *wg)
{
    int type = ((u8 *)buffer)[0];
    //int noise = type|(((u32)ktime_get_coarse_boottime_ns())<<3);
    //((__le32 *)buffer)[0] = cpu_to_le32(noise);
    
    switch (type) {
        case MESSAGE_HANDSHAKE_INITIATION:
            SKB_XOR1(buffer, HIDDEN_XOR);
            xor_mac2(buffer, sizeof(struct message_handshake_initiation), HIDDEN_XOR);
            break;

        case MESSAGE_HANDSHAKE_RESPONSE:
            SKB_XOR2(buffer, HIDDEN_XOR);
            xor_mac2(buffer, sizeof(struct message_handshake_response), HIDDEN_XOR);
            break;

        case MESSAGE_HANDSHAKE_COOKIE:
            SKB_XOR1(buffer, HIDDEN_XOR);
            break;
    }

    skb_put_hidden_header(skb, HIDDEN_HEADER_LEN_RAW((unsigned int)ktime_get_coarse_boottime_ns()));
}

unsigned int hidden_data_header_len(unsigned int len)
{
    return len != 32 ? 0 : HIDDEN_HEADER_LEN_RAW((unsigned int)ktime_get_coarse_boottime_ns());
}

void skb_put_hidden_data(void *skb, void *buffer, unsigned int hlen)
{
    //int noise = type|(((u32)ktime_get_coarse_boottime_ns())<<3);
    //((__le32 *)buffer)[0] = cpu_to_le32(noise);

    SKB_XOR3(buffer, HIDDEN_XOR);
    if(hlen > 0) skb_put_hidden_header(skb, hlen);
}
