#include "tlv.h"
#include <string.h>

int tlv_encode(uint8_t *out_buf, size_t out_buf_cap,
               uint8_t type, uint8_t seq,
               const void *payload, size_t payload_len)
{
    if (payload_len > TLV_MAX_PAYLOAD_SIZE) {
        return -2;
    }
    const size_t length_field = 2u + payload_len;
    const size_t total = 2u + length_field;
    if (total > out_buf_cap) {
        return -1;
    }

    out_buf[0] = (uint8_t)((length_field >> 8) & 0xFFu);
    out_buf[1] = (uint8_t)(length_field & 0xFFu);
    out_buf[2] = type;
    out_buf[3] = seq;
    if (payload && payload_len) {
        memcpy(out_buf + TLV_HEADER_SIZE, payload, payload_len);
    }
    return (int)total;
}

int tlv_decode(const uint8_t *in_buf, size_t in_buf_len,
               uint8_t *out_type, uint8_t *out_seq,
               const uint8_t **out_payload, size_t *out_payload_len)
{
    if (in_buf_len < TLV_HEADER_SIZE) {
        return -1;
    }
    const size_t length_field = ((size_t)in_buf[0] << 8) | (size_t)in_buf[1];
    if (length_field < 2u) {
        return -2;
    }
    const size_t total = 2u + length_field;
    if (total != in_buf_len) {
        return -2;
    }
    *out_type = in_buf[2];
    *out_seq = in_buf[3];
    *out_payload = in_buf + TLV_HEADER_SIZE;
    *out_payload_len = length_field - 2u;
    return 0;
}
