#include "command_router.h"
#include "transport_ble.h"
#include "scan_wifi.h"
#include "scan_ble.h"

#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_idf_version.h"
#include "esp_chip_info.h"
#include "esp_heap_caps.h"
#include "esp_app_desc.h"

static const char *TAG = "cmd-router";

static void send_json(cJSON *obj)
{
    char *buf = cJSON_PrintUnformatted(obj);
    if (!buf) {
        ESP_LOGW(TAG, "json print failed");
        return;
    }
    transport_ble_send_cmd((const uint8_t *)buf, strlen(buf));
    cJSON_free(buf);
}

static void send_err(int seq, const char *err, const char *msg)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "err", err);
    cJSON_AddNumberToObject(root, "seq", seq);
    if (msg) cJSON_AddStringToObject(root, "msg", msg);
    send_json(root);
    cJSON_Delete(root);
}

static int seq_of(cJSON *root)
{
    cJSON *seq = cJSON_GetObjectItemCaseSensitive(root, "seq");
    return (cJSON_IsNumber(seq)) ? seq->valueint : 0;
}

static void handle_ping(cJSON *root)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "resp", "pong");
    cJSON_AddNumberToObject(resp, "seq", seq_of(root));
    cJSON_AddNumberToObject(resp, "uptime_ms",
                            (double)(esp_timer_get_time() / 1000));
    send_json(resp);
    cJSON_Delete(resp);
}

static void handle_hello(cJSON *root)
{
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    const esp_app_desc_t *app = esp_app_get_description();

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "resp", "hello");
    cJSON_AddNumberToObject(resp, "seq", seq_of(root));
    cJSON_AddStringToObject(resp, "fw", app->version);
    cJSON_AddStringToObject(resp, "idf", esp_get_idf_version());
    cJSON_AddStringToObject(resp, "chip", "esp32s3");
    cJSON_AddNumberToObject(resp, "cores", chip.cores);
    cJSON_AddNumberToObject(resp, "rev", chip.revision);
    send_json(resp);
    cJSON_Delete(resp);
}

static void send_ack(int seq, const char *cmd)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "resp", cmd);
    cJSON_AddNumberToObject(resp, "seq", seq);
    cJSON_AddStringToObject(resp, "status", "started");
    send_json(resp);
    cJSON_Delete(resp);
}

static void handle_wifi_scan(cJSON *root)
{
    int seq = seq_of(root);
    esp_err_t err = scan_wifi_start_active();
    if (err == ESP_OK) {
        send_ack(seq, "wifi_scan");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "scan_busy", NULL);
    } else {
        send_err(seq, "scan_failed", esp_err_to_name(err));
    }
}

static void handle_ble_scan(cJSON *root)
{
    int seq = seq_of(root);
    cJSON *dur = cJSON_GetObjectItemCaseSensitive(root, "duration_sec");
    uint16_t duration = 10; // default 10s
    if (cJSON_IsNumber(dur) && dur->valueint >= 0 && dur->valueint < 600) {
        duration = (uint16_t)dur->valueint;
    }
    esp_err_t err = scan_ble_start(duration);
    if (err == ESP_OK) {
        send_ack(seq, "ble_scan");
    } else if (err == ESP_ERR_INVALID_STATE) {
        send_err(seq, "scan_busy", NULL);
    } else {
        send_err(seq, "scan_failed", esp_err_to_name(err));
    }
}

static void handle_ble_scan_stop(cJSON *root)
{
    int seq = seq_of(root);
    esp_err_t err = scan_ble_stop();
    if (err == ESP_OK) {
        send_ack(seq, "ble_scan_stop");
    } else {
        send_err(seq, "scan_idle", NULL);
    }
}

static void handle_status(cJSON *root)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "resp", "status");
    cJSON_AddNumberToObject(resp, "seq", seq_of(root));
    cJSON_AddNumberToObject(resp, "uptime_ms",
                            (double)(esp_timer_get_time() / 1000));
    cJSON_AddNumberToObject(resp, "free_sram",
                            heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(resp, "free_psram",
                            heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    cJSON_AddNumberToObject(resp, "min_free_sram",
                            heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
    send_json(resp);
    cJSON_Delete(resp);
}

void command_router_handle_json(const uint8_t *data, size_t len)
{
    cJSON *root = cJSON_ParseWithLength((const char *)data, len);
    if (!root) {
        ESP_LOGW(TAG, "json parse failed");
        send_err(0, "bad_json", NULL);
        return;
    }

    cJSON *cmd = cJSON_GetObjectItemCaseSensitive(root, "cmd");
    if (!cJSON_IsString(cmd) || !cmd->valuestring) {
        send_err(seq_of(root), "missing_cmd", NULL);
        cJSON_Delete(root);
        return;
    }

    const char *c = cmd->valuestring;
    if (strcmp(c, "ping") == 0) {
        handle_ping(root);
    } else if (strcmp(c, "hello") == 0) {
        handle_hello(root);
    } else if (strcmp(c, "status") == 0) {
        handle_status(root);
    } else if (strcmp(c, "wifi_scan") == 0) {
        handle_wifi_scan(root);
    } else if (strcmp(c, "ble_scan") == 0) {
        handle_ble_scan(root);
    } else if (strcmp(c, "ble_scan_stop") == 0) {
        handle_ble_scan_stop(root);
    } else {
        send_err(seq_of(root), "unknown_cmd", c);
    }

    cJSON_Delete(root);
}

esp_err_t command_router_init(void)
{
    ESP_LOGI(TAG, "ready (cmds: ping, hello, status, wifi_scan, ble_scan, ble_scan_stop)");
    return ESP_OK;
}
