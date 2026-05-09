#include "hidden.h"


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