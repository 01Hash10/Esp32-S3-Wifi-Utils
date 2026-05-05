// Tests Unity do componente protocol/tlv.
// Roda em hardware via `pio test -e esp32-s3-devkitc-1` ou
// `pio test -e esp32-s3-devkitc-1 -f test_tlv`.

#include <string.h>
#include "unity.h"
#include "tlv.h"

void setUp(void) {}
void tearDown(void) {}

TEST_CASE("encode payload simples", "[tlv]")
{
    uint8_t out[64];
    uint8_t payload[] = {0x11, 0x22, 0x33};
    int total = tlv_encode(out, sizeof(out), TLV_MSG_HEARTBEAT, 7,
                           payload, sizeof(payload));
    TEST_ASSERT_EQUAL_INT(7, total); // 2 length + 1 type + 1 seq + 3 payload
    // length field = type(1) + seq(1) + payload(3) = 5
    TEST_ASSERT_EQUAL_UINT8(0x00, out[0]);
    TEST_ASSERT_EQUAL_UINT8(0x05, out[1]);
    TEST_ASSERT_EQUAL_UINT8(TLV_MSG_HEARTBEAT, out[2]);
    TEST_ASSERT_EQUAL_UINT8(7, out[3]);
    TEST_ASSERT_EQUAL_UINT8(0x11, out[4]);
    TEST_ASSERT_EQUAL_UINT8(0x22, out[5]);
    TEST_ASSERT_EQUAL_UINT8(0x33, out[6]);
}

TEST_CASE("encode sem payload", "[tlv]")
{
    uint8_t out[16];
    int total = tlv_encode(out, sizeof(out), 0x42, 99, NULL, 0);
    TEST_ASSERT_EQUAL_INT(4, total);
    TEST_ASSERT_EQUAL_UINT8(0x00, out[0]);
    TEST_ASSERT_EQUAL_UINT8(0x02, out[1]);
    TEST_ASSERT_EQUAL_UINT8(0x42, out[2]);
    TEST_ASSERT_EQUAL_UINT8(99, out[3]);
}

TEST_CASE("encode payload tamanho máximo", "[tlv]")
{
    uint8_t out[TLV_MAX_FRAME_SIZE];
    uint8_t payload[TLV_MAX_PAYLOAD_SIZE];
    memset(payload, 0xAB, sizeof(payload));
    int total = tlv_encode(out, sizeof(out), 0x10, 0, payload, sizeof(payload));
    TEST_ASSERT_EQUAL_INT(TLV_MAX_FRAME_SIZE, total);
    TEST_ASSERT_EQUAL_UINT8(0xAB, out[TLV_HEADER_SIZE]);
    TEST_ASSERT_EQUAL_UINT8(0xAB, out[TLV_MAX_FRAME_SIZE - 1]);
}

TEST_CASE("encode falha se buf muito pequeno", "[tlv]")
{
    uint8_t out[5];
    uint8_t payload[] = {1, 2, 3, 4};
    int rc = tlv_encode(out, sizeof(out), 0x10, 0, payload, sizeof(payload));
    TEST_ASSERT_EQUAL_INT(-1, rc); // total = 8 > cap 5
}

TEST_CASE("encode falha se payload acima do max", "[tlv]")
{
    uint8_t out[TLV_MAX_FRAME_SIZE + 10];
    uint8_t payload[TLV_MAX_PAYLOAD_SIZE + 1];
    int rc = tlv_encode(out, sizeof(out), 0x10, 0, payload, sizeof(payload));
    TEST_ASSERT_EQUAL_INT(-2, rc);
}

TEST_CASE("decode válido — round-trip", "[tlv]")
{
    uint8_t out[64];
    uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
    int total = tlv_encode(out, sizeof(out), 0x33, 5, payload, sizeof(payload));
    TEST_ASSERT_GREATER_THAN_INT(0, total);

    uint8_t type, seq;
    const uint8_t *p_out;
    size_t p_len;
    int rc = tlv_decode(out, total, &type, &seq, &p_out, &p_len);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_UINT8(0x33, type);
    TEST_ASSERT_EQUAL_UINT8(5, seq);
    TEST_ASSERT_EQUAL_size_t(sizeof(payload), p_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload, p_out, sizeof(payload));
}

TEST_CASE("decode frame pequeno demais", "[tlv]")
{
    uint8_t buf[3] = {0x00, 0x02, 0x10}; // header 4 bytes mín
    uint8_t type, seq;
    const uint8_t *p_out;
    size_t p_len;
    int rc = tlv_decode(buf, sizeof(buf), &type, &seq, &p_out, &p_len);
    TEST_ASSERT_EQUAL_INT(-1, rc);
}

TEST_CASE("decode com inconsistência de length", "[tlv]")
{
    // Length declarado = 5 (type + seq + 3 payload), buf real só 6 bytes
    uint8_t buf[6] = {0x00, 0x05, 0x10, 0x00, 0xAA, 0xBB};
    // total = 2 + 5 = 7, mas buf é 6 → falha
    uint8_t type, seq;
    const uint8_t *p_out;
    size_t p_len;
    int rc = tlv_decode(buf, sizeof(buf), &type, &seq, &p_out, &p_len);
    TEST_ASSERT_EQUAL_INT(-2, rc);
}

TEST_CASE("decode com length=1 (sem type+seq) inválido", "[tlv]")
{
    uint8_t buf[4] = {0x00, 0x01, 0x10, 0x00};
    uint8_t type, seq;
    const uint8_t *p_out;
    size_t p_len;
    int rc = tlv_decode(buf, sizeof(buf), &type, &seq, &p_out, &p_len);
    TEST_ASSERT_EQUAL_INT(-2, rc);
}

void app_main(void)
{
    UNITY_BEGIN();
    unity_run_all_tests();
    UNITY_END();
}
