#include "hidden.h"



size_t prepare_skb_hidden(struct sk_buff *skb, struct wg_device *wg) 
{
    __le32 type;
    size_t hlen = 0;

    if (unlikely(!pskb_may_pull(skb, 5)))
        return ERROR_HIDDEN_LEN;

    type = ((u8 *)skb->data)[0];

    if(HIDDEN_TYPE(type) == 0)
    {
        hlen = HIDDEN_HEADER_LEN(type>>3);
        type = HIDDEN_TYPE(((u8 *)skb->data)[hlen]);
    }

    if (unlikely(!pskb_may_pull(skb, hlen + sizeof(struct message_header))))
        return ERROR_HIDDEN_LEN;

    ((struct message_header *)(((u8 *)skb->data)+hlen))->type = le32_to_cpu(type);

    switch (type) {
        case MESSAGE_DATA:
            if (unlikely(!pskb_may_pull(skb, hlen + 16)))
                return ERROR_HIDDEN_LEN;
            break;

        case MESSAGE_HANDSHAKE_INITIATION:
            if (unlikely(!pskb_may_pull(skb, hlen + 8)))
                return ERROR_HIDDEN_LEN;
            break;

        case MESSAGE_HANDSHAKE_RESPONSE:
            
            break;

        case MESSAGE_HANDSHAKE_COOKIE:
        
            break;

        default:
            
            break;
    }

    return hlen;
}


void skb_put_hidden_data(void *skb, void *buffer, size_t len)
{
    ((u8 *)buffer)[2]=0xAA;
    ((u8 *)buffer)[3]=0xbb;
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

void skb_put_hidden_header(void *skb, struct hidden_header *header)
{
    u32 noise;
    u8 *ptr = (u8 *)skb_push(skb, header->len);
    
    ptr[0]=header->val;

    if(header->len > 1)
    {
        noise = ktime_get_coarse_boottime_ns()>>(header->len);
        memcpy(ptr+1, &noise, header->len - 1);
        //get_random_bytes(ptr+1, header->len - 1);
    }
}