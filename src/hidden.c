#include "hidden.h"


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

void skb_put_hidden_header(void *skb)
{
    int hlen;
    u8 *ptr;
    u8 noise = ktime_get_coarse_boottime_ns()<<3;
    if(noise<16) noise |= 128;
    hlen = HIDDEN_HEADER_LEN(noise);
    ptr = (u8 *)skb_push(skb, hlen);
    ptr[0] = noise;
    if(hlen>1) get_random_bytes(ptr+1, hlen-1);
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
            skb_put_hidden_header(skb);
            break;

        case MESSAGE_HANDSHAKE_RESPONSE:
            SKB_XOR2(buffer, HIDDEN_XOR);
            xor_mac2(buffer, sizeof(struct message_handshake_response), HIDDEN_XOR);
            skb_put_hidden_header(skb);
            break;

        case MESSAGE_HANDSHAKE_COOKIE:
            SKB_XOR1(buffer, HIDDEN_XOR);
            skb_put_hidden_header(skb);
            break;
    }
}

void skb_put_hidden_data(void *skb, void *buffer, size_t len)
{
    int type = ((u8 *)buffer)[0];
    //int noise = type|(((u32)ktime_get_coarse_boottime_ns())<<3);
    //((__le32 *)buffer)[0] = cpu_to_le32(noise);
    
    switch (type) {
        case MESSAGE_DATA:
            SKB_XOR3(buffer, HIDDEN_XOR);
            //if(len==32) skb_put_hidden_header(skb);
            break;

        case MESSAGE_HANDSHAKE_INITIATION:
            SKB_XOR1(buffer, HIDDEN_XOR);
            xor_mac2(buffer, sizeof(struct message_handshake_initiation), HIDDEN_XOR);
            skb_put_hidden_header(skb);
            break;

        case MESSAGE_HANDSHAKE_RESPONSE:
            SKB_XOR2(buffer, HIDDEN_XOR);
            xor_mac2(buffer, sizeof(struct message_handshake_response), HIDDEN_XOR);
            skb_put_hidden_header(skb);
            break;

        case MESSAGE_HANDSHAKE_COOKIE:
            SKB_XOR1(buffer, HIDDEN_XOR);
            skb_put_hidden_header(skb);
            break;
    }
}




__le32 hidden_type(enum message_type type) 
{
    __le32 val = ktime_get_coarse_boottime_ns();
    //get_random_bytes(&val, sizeof(val));
    ((u8 *)&val)[0] += type - HIDDEN_TYPE(val);
    return val;
}

void hidden_header_init(struct hidden_header *header, enum message_type type)
{
    header->val = 0;
    get_random_bytes(&header->val, 1);
    if(header->val < 16) header->val |= 0x10;
    header->len = HIDDEN_HEADER_LEN(header->val);
}

