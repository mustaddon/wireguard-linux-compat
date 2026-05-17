#include "hidden.h"
#include "messages.h"

static const unsigned char MASK[32] = { 
    0x81, 0xab, 0xa4, 0x0d, 0xb7, 0x73, 0x42, 0x2b, 
    0xd0, 0x79, 0x2d, 0x65, 0xce, 0x69, 0x1f, 0x82, 
    0x98, 0x31, 0x89, 0xaf, 0xd6, 0x5c, 0x85, 0x93, 
    0x8b, 0x90, 0x52, 0x33, 0x17, 0xff, 0x18, 0x57 };

#define HIDDEN_HEADER_LEN(val) 0// (((val)&3) + 1)
#define SKB_HIDDEN_HEADER_LEN(skb) HIDDEN_HEADER_LEN(((u8 *)(skb))[2])
#define HIDDEN_TYPE(val) ((val)&7)
#define SKB_HIDDEN_TYPE(skb) HIDDEN_TYPE(((u8 *)(skb))[1])

#define	U8_MASK(wg) (MASK)
#define	U32_MASK(wg) (((u32 *)(MASK)))
#define	XOR_HEAD(skb, wg) ((u32 *)(skb))[0]^=(U32_MASK(wg))[0]
#define	XOR_HEAD_CALC(skb, wg) ((u32 *)(skb))[0]^(U32_MASK(wg))[0]

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
    ptr[1] ^= ptr[0]^mask[1];
    xor_mac2(skb, sizeof(struct message_handshake_initiation), ptr[0], mask);
}

static void xor_resp(void *skb, struct wg_device *wg)
{
    u32 *mask = U32_MASK(wg);
    u32 *ptr = (u32 *)(skb);
    ptr[1] ^= ptr[0]^mask[1];
    ptr[2] ^= ptr[0]^mask[2];
    xor_mac2(skb, sizeof(struct message_handshake_response), ptr[0], mask);
}

static void xor_cook(void *skb, struct wg_device *wg)
{
    u32 *mask = U32_MASK(wg);
    u32 *ptr = (u32 *)(skb);
    ptr[1] ^= ptr[0]^mask[1];
}

static void xor_data(void *skb, struct wg_device *wg)
{
    u32 *mask = U32_MASK(wg);
    u32 *ptr = (u32 *)(skb);
    ptr[1] ^= ptr[0]^mask[1];
    ptr[2] ^= ptr[0]^mask[2];
    ptr[3] ^= ptr[0]^mask[3];
}

size_t prepare_skb_hidden(struct sk_buff *skb, struct wg_device *wg) 
{
    int type;
    size_t hlen = 0;
    u32 head_tmp;

    if (unlikely(!pskb_may_pull(skb, 32)))
        return ERROR_HIDDEN_LEN;

    if (((u8 *)(skb->data))[0] == 0xc0 || ((u8 *)(skb->data))[0] == 0xd0)
    {
        hlen = sizeof(struct QUIC_message_handshake);
        skb_pull(skb, hlen);
    }

    //head_tmp = XOR_HEAD_CALC(skb->data, wg);
    type = SKB_HIDDEN_TYPE(skb->data); //SKB_HIDDEN_TYPE(&head_tmp);
    
    if(type == 0)
    {
        hlen += SKB_HIDDEN_HEADER_LEN(skb->data);
        skb_pull(skb, hlen);
        //XOR_HEAD(skb->data, wg);
        type = SKB_HIDDEN_TYPE(skb->data);
    }

    switch (type) {
        case MESSAGE_DATA:
            if (unlikely(!pskb_may_pull(skb, sizeof(struct message_data))))
                return ERROR_HIDDEN_LEN;
            //xor_data(skb->data, wg);
            break;

        case MESSAGE_HANDSHAKE_INITIATION:
            if (unlikely(!pskb_may_pull(skb, sizeof(struct message_handshake_initiation))))
                return ERROR_HIDDEN_LEN;
            //xor_init(skb->data, wg);
            break;

        case MESSAGE_HANDSHAKE_RESPONSE:
            if (unlikely(!pskb_may_pull(skb, sizeof(struct message_handshake_response))))
                return ERROR_HIDDEN_LEN;
            //xor_resp(skb->data, wg);
            break;

        case MESSAGE_HANDSHAKE_COOKIE:
            if (unlikely(!pskb_may_pull(skb, 8)))
                return ERROR_HIDDEN_LEN;
            //xor_cook(skb->data, wg);
            break;

        default:
            return ERROR_HIDDEN_LEN;
    }

    ((__le32 *)(skb->data))[0] = cpu_to_le32(type);

    return hlen;
}

static void skb_put_quic_header(void *skb, size_t data_len, int type)
{
    struct QUIC_message_handshake *quic = (struct QUIC_message_handshake *)skb_push(skb, sizeof(struct QUIC_message_handshake));
    quic->version = cpu_to_be32(1);
	quic->token_len = 0;
	quic->data_len = cpu_to_be16(0x4000 | data_len);

    if (type == MESSAGE_HANDSHAKE_INITIATION)
    {
        quic->flags = 0xc0;
        quic->CID.initiation.DCID_len = sizeof(quic->CID.initiation.DCID);
        quic->CID.initiation.DCID = ktime_get_coarse_boottime_ns();
        quic->CID.initiation.SCID_len = 0;
    }
    else
    {
        quic->flags = 0xd0;
        quic->CID.response.DCID_len = 0;
        quic->CID.response.SCID_len = sizeof(quic->CID.response.SCID);
        quic->CID.response.SCID = ktime_get_coarse_boottime_ns();
    }
}

static void add_quick_init(void *skb, size_t data_len)
{
    struct QUIC_message_handshake *quic = (struct QUIC_message_handshake *)skb_push(skb, sizeof(struct QUIC_message_handshake));
    quic->version = cpu_to_be32(1);
    quic->flags = 0xc0;
    quic->CID.initiation.DCID_len = sizeof(quic->CID.initiation.DCID);
    quic->CID.initiation.DCID = 1;//ktime_get_coarse_boottime_ns();
    quic->CID.initiation.SCID_len = 0;
	quic->token_len = 0;
	quic->data_len = cpu_to_be16(0x4000 | data_len);
}

static void add_quick_resp(void *skb, size_t data_len)
{
    struct QUIC_message_handshake *quic = (struct QUIC_message_handshake *)skb_push(skb, sizeof(struct QUIC_message_handshake));
    quic->version = cpu_to_be32(1);
    quic->flags = 0xd0;
    quic->CID.response.DCID_len = 0;
    quic->CID.response.SCID_len = 1;// sizeof(quic->CID.response.SCID);
    quic->CID.response.SCID = ktime_get_coarse_boottime_ns();
	quic->token_len = 0;
	quic->data_len = cpu_to_be16(0x4000 | data_len);
}

static void skb_put_hidden_header(void *skb, unsigned int hlen, struct wg_device *wg)
{
    u8 *buffer = (u8 *)skb_push(skb, hlen);
    u32 noise = ((u32)ktime_get_coarse_boottime_ns()<<5) | ((hlen-1)<<3);
    noise = cpu_to_le32(noise);
    memcpy(buffer, &noise, hlen);
    buffer[0]^=U8_MASK(wg)[0];
}

static void skb_add_type_noise(void *buffer)
{
    u8 type = ((u8 *)buffer)[0];
    ((u32 *)buffer)[0] = ktime_get_coarse_boottime_ns();
    ((u8 *)buffer)[0] = 0x43;
    ((u8 *)buffer)[1] = type;// (((u8 *)buffer)[0]<<3) | type;
    ((u8 *)buffer)[2] = 0;
}

void skb_put_hidden_handshake(void *skb, void *buffer, struct wg_device *wg)
{
    size_t data_len;
    int type = ((u8 *)buffer)[0];
    unsigned int hlen = 0;// HIDDEN_HEADER_LEN((unsigned int)ktime_get_coarse_boottime_ns());
    skb_add_type_noise(buffer);
    
    switch (type) {
        case MESSAGE_HANDSHAKE_INITIATION:
            //xor_init(buffer, wg);
            data_len = sizeof(struct message_handshake_initiation) + hlen;
            add_quick_init(skb, data_len);
            break;

        case MESSAGE_HANDSHAKE_RESPONSE:
            //xor_resp(buffer, wg);
            data_len = sizeof(struct message_handshake_response) + hlen;
            add_quick_resp(skb, data_len);
            break;

        case MESSAGE_HANDSHAKE_COOKIE:
            //xor_cook(buffer, wg);
            //data_len = sizeof(struct message_handshake_cookie) + hlen;
            break;
    }

    //XOR_HEAD(buffer, wg);
    //skb_put_hidden_header(skb, hlen, wg);
    //skb_put_quic_header(skb, data_len, type);
}

unsigned int hidden_data_header_len(unsigned int len)
{
    return len != 32 ? 0 : HIDDEN_HEADER_LEN((unsigned int)ktime_get_coarse_boottime_ns());
}

void skb_put_hidden_data(void *skb, void *buffer, unsigned int hlen, struct wg_device *wg)
{
    skb_add_type_noise(buffer);
    //xor_data(buffer, wg);
    //XOR_HEAD(buffer, wg);

    if(hlen > 0) 
    {
        //skb_put_hidden_header(skb, hlen, wg);
    }
}
