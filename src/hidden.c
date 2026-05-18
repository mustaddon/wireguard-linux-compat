#include "hidden.h"
#include "messages.h"

static const unsigned char MASK[32] = { 
    0x81, 0xab, 0xa4, 0x0d, 0xb7, 0x73, 0x42, 0x2b, 
    0xd0, 0x79, 0x2d, 0x65, 0xce, 0x69, 0x1f, 0x82, 
    0x98, 0x31, 0x89, 0xaf, 0xd6, 0x5c, 0x85, 0x93, 
    0x8b, 0x90, 0x52, 0x33, 0x17, 0xff, 0x18, 0x57 };

#define HIDDEN_HEADER_LEN(val) ((val)&7)
#define SKB_HIDDEN_HEADER_LEN(skb) HIDDEN_HEADER_LEN(((u8 *)(skb))[0])
#define HIDDEN_TYPE(val) ((val)&7)
#define SKB_HIDDEN_TYPE(skb) HIDDEN_TYPE(((u8 *)(skb))[1])

#define	U8_MASK(wg) (MASK)
#define	U32_MASK(wg) (((u32 *)(MASK)))
#define	XOR_HEAD(skb, wg) ((u8 *)(skb))[0]=(((u8 *)(skb))[0]&0xF0)|((((u8 *)(skb))[0]^U8_MASK(wg)[0])&0x0F)


static void xor_mac2(void *skb, size_t len, u32 zero, u32 *mask)
{
    u32 *ptr = (u32 *)((u8 *)skb + len - 16);
    ptr[0] ^= zero^mask[4];
    ptr[1] ^= zero^mask[5];
    ptr[2] ^= zero^mask[6];
    ptr[3] ^= zero^mask[7];
}

static void xor_init(void *skb, struct wg_device *wg)
{
    u32 *mask = U32_MASK(wg);
    u32 *ptr = (u32 *)(skb);
    u32 zero = ptr[0]^mask[0];
    ptr[1] ^= zero^mask[1];
    xor_mac2(skb, sizeof(struct message_handshake_initiation), zero, mask);
}

static void xor_resp(void *skb, struct wg_device *wg)
{
    u32 *mask = U32_MASK(wg);
    u32 *ptr = (u32 *)(skb);
    u32 zero = ptr[0]^mask[0];
    ptr[1] ^= zero^mask[1];
    ptr[2] ^= zero^mask[2];
    xor_mac2(skb, sizeof(struct message_handshake_response), zero, mask);
}

static void xor_cook(void *skb, struct wg_device *wg)
{
    u32 *mask = U32_MASK(wg);
    u32 *ptr = (u32 *)(skb);
    u32 zero = ptr[0]^mask[0];
    ptr[1] ^= zero^mask[1];
}

static void xor_data(void *skb, struct wg_device *wg)
{
    u32 *mask = U32_MASK(wg);
    u32 *ptr = (u32 *)(skb);
    u32 zero = ptr[0]^mask[0];
    ptr[1] ^= zero^mask[1];
    ptr[2] ^= zero^mask[2];
    ptr[3] ^= zero^mask[3];
}

size_t prepare_skb_hidden(struct sk_buff *skb, struct wg_device *wg) 
{
    int type;
    size_t hlen;

    if (unlikely(!pskb_may_pull(skb, 32)))
        return ERROR_HIDDEN_LEN;

    XOR_HEAD(skb->data, wg);
    hlen = HIDDEN_HEADER_LEN(((u8 *)(skb->data))[0]);

    if (((u8 *)(skb->data))[0] & 0x80)
    {
        if(((u8 *)(skb->data))[5] != 3)
        {
            hlen += QUIC_INIT_LEN;
            type = MESSAGE_HANDSHAKE_INITIATION;
        }
        else if(((u8 *)(skb->data))[9] != 0)
        {
            hlen += QUIC_RESP_LEN;
            type = MESSAGE_HANDSHAKE_RESPONSE;
        }
        else 
        {
            hlen += QUIC_COOK_LEN;
            type = MESSAGE_HANDSHAKE_COOKIE;
        }
        skb_pull(skb, hlen);
    }
    else
    {
        type = MESSAGE_DATA;
        if (hlen > 0)
        {
            hlen += QUIC_DATA_LEN;
            skb_pull(skb, hlen);
        }
    }

    switch (type) {
        case MESSAGE_DATA:
            if (unlikely(!pskb_may_pull(skb, sizeof(struct message_data))))
                return ERROR_HIDDEN_LEN;
            xor_data(skb->data, wg);
            break;

        case MESSAGE_HANDSHAKE_INITIATION:
            if (unlikely(!pskb_may_pull(skb, sizeof(struct message_handshake_initiation))))
                return ERROR_HIDDEN_LEN;
            xor_init(skb->data, wg);
            break;

        case MESSAGE_HANDSHAKE_RESPONSE:
            if (unlikely(!pskb_may_pull(skb, sizeof(struct message_handshake_response))))
                return ERROR_HIDDEN_LEN;
            xor_resp(skb->data, wg);
            break;

        case MESSAGE_HANDSHAKE_COOKIE:
            if (unlikely(!pskb_may_pull(skb, 8)))
                return ERROR_HIDDEN_LEN;
            xor_cook(skb->data, wg);
            break;

        default:
            return ERROR_HIDDEN_LEN;
    }

    ((__le32 *)(skb->data))[0] = cpu_to_le32(type);

    return hlen;
}

#define QUICK_FLAGS_INIT ((((u8)ktime_get_coarse_boottime_ns())&0x0F) | 0xC0)
static const __be32 quic_version = cpu_to_be32(1);

static void add_quick_init_start(u8 flags, struct QUIC_init_start *quic)
{
    quic->flags = flags;
    quic->version = quic_version;
}

static void add_quick_init_end(size_t dlen, struct QUIC_init_end *quic)
{
    quic->token_len = 0;
	quic->data_len = cpu_to_be16(0x4000 | dlen);
}


static void add_quick_init(struct message_handshake_initiation *data, struct QUIC_init *quic)
{
    quic->DCID_len = sizeof(quic->DCID);
    get_random_bytes(&quic->DCID, quic->DCID_len);
    ((u32 *)(&quic->SCID_len))[0] = data->sender_index;
    quic->SCID_len = sizeof(quic->SCID);
}

static void add_quick_resp(struct message_handshake_response *data, struct QUIC_resp *quic)
{
    ((u32 *)(&quic->DCID_len))[0] = data->receiver_index;
    quic->DCID_len = sizeof(quic->DCID);
    ((u32 *)(&quic->SCID_len))[0] = data->sender_index;
    quic->SCID_len = sizeof(quic->SCID);
}

static void add_quick_cook(struct message_handshake_cookie *data, struct QUIC_cook *quic)
{
    ((u32 *)(&quic->DCID_len))[0] = data->receiver_index;
    quic->DCID_len = sizeof(quic->DCID);
    quic->SCID_len = 0;
}

void skb_put_hidden_handshake(void *skb, void *buffer, struct wg_device *wg)
{
    u8 type = ((u8 *)buffer)[0];
    u8 flags = 0xC0 | (((u8)ktime_get_coarse_boottime_ns())&0x0F);
    size_t qlen, dlen, hlen = HIDDEN_HEADER_LEN(flags);
    u8 *quic;
    
    ((u32 *)buffer)[0] = ktime_get_coarse_boottime_ns();
    
    switch (type) {
        case MESSAGE_HANDSHAKE_INITIATION:
            dlen = sizeof(struct message_handshake_initiation);
            qlen = QUIC_INIT_LEN;
            quic = (u8 *)skb_push(skb, qlen + hlen);
            add_quick_init((struct message_handshake_initiation *)buffer,
                (struct QUIC_init *)(quic + sizeof(struct QUIC_init_start)));
            xor_init(buffer, wg);
            break;

        case MESSAGE_HANDSHAKE_RESPONSE:
            dlen = sizeof(struct message_handshake_response);
            qlen = QUIC_RESP_LEN;
            quic = (u8 *)skb_push(skb, qlen + hlen);
            add_quick_resp((struct message_handshake_response *)buffer,
                (struct QUIC_resp *)(quic + sizeof(struct QUIC_init_start)));
            xor_resp(buffer, wg);
            break;

        case MESSAGE_HANDSHAKE_COOKIE:
            dlen = sizeof(struct message_handshake_cookie);
            qlen = QUIC_COOK_LEN;
            quic = (u8 *)skb_push(skb, qlen + hlen);
            add_quick_cook((struct message_handshake_cookie *)buffer,
                (struct QUIC_cook *)(quic + sizeof(struct QUIC_init_start)));
            xor_cook(buffer, wg);
            break;
    }

    add_quick_init_start(flags, (struct QUIC_init_start *)quic);
    add_quick_init_end(dlen + hlen, (struct QUIC_init_end *)(quic + qlen - sizeof(struct QUIC_init_end)));
    if (hlen > 0) get_random_bytes(quic+qlen, hlen);

    XOR_HEAD(quic, wg);
}

unsigned int hidden_data_header_len(unsigned int len)
{
    if(len != 32) return 0;

    return HIDDEN_HEADER_LEN((unsigned int)ktime_get_coarse_boottime_ns()) + QUIC_DATA_LEN;
}

void skb_put_hidden_data(void *skb, void *buffer, unsigned int hlen, struct wg_device *wg)
{
    u8 *quic = (u8 *)buffer;

    if (hlen > 0) 
    {
        quic = (u8 *)skb_push(skb, hlen);
        hlen -= QUIC_DATA_LEN;
        ((u32 *)quic)[0] = ((struct message_data *)buffer)->key_idx;
        ((u32 *)buffer)[0] = ktime_get_coarse_boottime_ns();
        quic[0] = (((u32 *)buffer)[0]&0x18) | 0x40 | hlen;
        if (hlen > 0) get_random_bytes(quic+4, hlen);
    }
    else
    {
        ((u32 *)buffer)[0] = ((struct message_data *)buffer)->key_idx;
        quic[0] = (((u8)ktime_get_coarse_boottime_ns())&0x18) | 0x40;
    }

    xor_data(buffer, wg);
    XOR_HEAD(quic, wg);
}
