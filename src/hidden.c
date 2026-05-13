#include "hidden.h"
#include "messages.h"

const unsigned char mask[32] = { 
    0x81, 0xab, 0xa4, 0x0d, 0xb7, 0x73, 0x42, 0x2b, 
    0xd0, 0x79, 0x2d, 0x65, 0xce, 0x69, 0x1f, 0x82, 
    0x98, 0x31, 0x89, 0xaf, 0xd6, 0x5c, 0x85, 0x93, 
    0x8b, 0x90, 0x52, 0x33, 0x17, 0xff, 0x18, 0x57 };

#define HIDDEN_TYPE(val) ((val)&7)
#define SKB_HIDDEN_TYPE(skb, offset) HIDDEN_TYPE(((u8 *)(skb))[3+offset])

#define HIDDEN_HEADER_LEN_RAW(val) (11)// (((val)&7) + 4)
#define HIDDEN_HEADER_LEN(val) HIDDEN_HEADER_LEN_RAW((val)>>3)
#define SKB_HIDDEN_HEADER_LEN(skb) HIDDEN_HEADER_LEN(((u8 *)(skb))[3])

#define	GET_XOR(skb, wg, i) ((((int *)(skb))[0])^(((int *)(mask))[i]))
#define	SKB_XOR(skb, wg, i) ((int *)(skb))[i]^=GET_XOR(skb, wg, i)
#define	XOR_HEAD(skb, wg) ((int *)(skb))[0]^=(((int *)(mask))[0])
#define	XOR_HS_INIT(skb, wg) SKB_XOR(skb, wg, 1)
#define	XOR_HS_RESP(skb, wg) SKB_XOR(skb, wg, 1);SKB_XOR(skb, wg, 2)
#define	XOR_HS_COOK(skb, wg) SKB_XOR(skb, wg, 1)
#define	XOR_DATA(skb, wg) SKB_XOR(skb, wg, 1);SKB_XOR(skb, wg, 2);SKB_XOR(skb, wg, 3)

static void xor_mac2(void *skb, size_t len, struct wg_device *wg)
{
    int *ptr = (int *)((u8 *)skb + len - 16);
    ptr[0] ^= GET_XOR(skb, wg, 4);
    ptr[1] ^= GET_XOR(skb, wg, 5);
    ptr[2] ^= GET_XOR(skb, wg, 6);
    ptr[3] ^= GET_XOR(skb, wg, 7);
}

size_t prepare_skb_hidden(struct sk_buff *skb, struct wg_device *wg) 
{
    int type;
    size_t hlen = 0;

    if (unlikely(!pskb_may_pull(skb, 32)))
        return ERROR_HIDDEN_LEN;

    XOR_HEAD(skb->data, wg);
    type = SKB_HIDDEN_TYPE(skb->data, 0);

    if(type == 0)
    {
        hlen = SKB_HIDDEN_HEADER_LEN(skb->data);
        skb_pull(skb, hlen);
        XOR_HEAD(skb->data, wg);
        type = SKB_HIDDEN_TYPE(skb->data, 0);
    }

    switch (type) {
        case MESSAGE_DATA:
            if (unlikely(!pskb_may_pull(skb, sizeof(struct message_data))))
                return ERROR_HIDDEN_LEN;
            XOR_DATA(skb->data, wg);
            break;

        case MESSAGE_HANDSHAKE_INITIATION:
            if (unlikely(!pskb_may_pull(skb, sizeof(struct message_handshake_initiation))))
                return ERROR_HIDDEN_LEN;
            XOR_HS_INIT(skb->data, wg);
            xor_mac2(skb->data, sizeof(struct message_handshake_initiation), wg);
            break;

        case MESSAGE_HANDSHAKE_RESPONSE:
            if (unlikely(!pskb_may_pull(skb, sizeof(struct message_handshake_response))))
                return ERROR_HIDDEN_LEN;
            XOR_HS_RESP(skb->data, wg);
            xor_mac2(skb->data, sizeof(struct message_handshake_response), wg);
            break;

        case MESSAGE_HANDSHAKE_COOKIE:
            if (unlikely(!pskb_may_pull(skb, 8)))
                return ERROR_HIDDEN_LEN;
            XOR_HS_COOK(skb->data, wg);
            break;

        default:
            return ERROR_HIDDEN_LEN;
    }

    ((__le32 *)(skb->data))[0] = cpu_to_le32(type);

    return hlen;
}

static void skb_put_hidden_header(void *skb, unsigned int hlen, struct wg_device *wg)
{
    u8 *buffer = (u8 *)skb_push(skb, hlen);
    get_random_bytes(buffer, hlen);
    buffer[3] = (buffer[3]<<6) | ((hlen-4)<<3);
    XOR_HEAD(buffer, wg);
}

static void skb_add_type_noise(void *buffer)
{
    u8 type = ((u8 *)buffer)[0];
    ((u32 *)buffer)[0] = ktime_get_coarse_boottime_ns();
    ((u8 *)buffer)[3] = (((u8 *)buffer)[3]<<3) | type;
}

void skb_put_hidden_handshake(void *skb, void *buffer, struct wg_device *wg)
{
    int type = ((u8 *)buffer)[0];
    skb_add_type_noise(buffer);
    
    switch (type) {
        case MESSAGE_HANDSHAKE_INITIATION:
            XOR_HS_INIT(buffer, wg);
            xor_mac2(buffer, sizeof(struct message_handshake_initiation), wg);
            break;

        case MESSAGE_HANDSHAKE_RESPONSE:
            XOR_HS_RESP(buffer, wg);
            xor_mac2(buffer, sizeof(struct message_handshake_response), wg);
            break;

        case MESSAGE_HANDSHAKE_COOKIE:
            XOR_HS_COOK(buffer, wg);
            break;
    }

    XOR_HEAD(buffer, wg);
    skb_put_hidden_header(skb, HIDDEN_HEADER_LEN_RAW((unsigned int)ktime_get_coarse_boottime_ns()), wg);
}

unsigned int hidden_data_header_len(unsigned int len)
{
    return len != 32 ? 0 : HIDDEN_HEADER_LEN_RAW((unsigned int)ktime_get_coarse_boottime_ns());
}

void skb_put_hidden_data(void *skb, void *buffer, unsigned int hlen, struct wg_device *wg)
{
    skb_add_type_noise(buffer);
    XOR_DATA(buffer, wg);
    XOR_HEAD(buffer, wg);
    
    if(hlen > 0) 
    {
        skb_put_hidden_header(skb, hlen, wg);
    }
    else
    {
        //XOR_HEAD(buffer, wg);
    }
}
