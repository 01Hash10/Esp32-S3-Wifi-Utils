#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_chip_info.h"
#include "esp_idf_version.h"
#include "esp_heap_caps.h"
#include "esp_log.h"

#include "transport_ble.h"
#include "command_router.h"
#include "scan_wifi.h"
#include "scan_ble.h"
#include "hacking_wifi.h"
#include "hacking_ble.h"
#include "attack_lan.h"
#include "sniff_wifi.h"
#include "evil_twin.h"
#include "captive_portal.h"
#include "watchdog.h"
#include "persist.h"
#include "playbook.h"

static const char *TAG = "boot-diag";

static void log_mem(void)
{
    size_t free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t free_psram    = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    size_t total_psram   = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);

    ESP_LOGI(TAG, "ESP-IDF       : %s", esp_get_idf_version());
    ESP_LOGI(TAG, "Free SRAM     : %u bytes (%.1f KB)",
             (unsigned)free_internal, free_internal / 1024.0f);
    ESP_LOGI(TAG, "Free PSRAM    : %u bytes (%.2f MB)",
             (unsigned)free_psram, free_psram / (1024.0f * 1024.0f));
    ESP_LOGI(TAG, "Total PSRAM   : %u bytes", (unsigned)total_psram);
}

void app_main(void)
{
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    ESP_LOGI(TAG, "Chip          : %s rev v%d.%d, %d core(s)",
             CONFIG_IDF_TARGET, chip.revision / 100, chip.revision % 100, chip.cores);

    ESP_ERROR_CHECK(command_router_init());
    ESP_ERROR_CHECK(transport_ble_init(command_router_handle_json));
    ESP_ERROR_CHECK(scan_wifi_init(transport_ble_send_stream));
    ESP_ERROR_CHECK(scan_ble_init(transport_ble_send_stream));
    ESP_ERROR_CHECK(hacking_wifi_init());
    ESP_ERROR_CHECK(hacking_ble_init());
    ESP_ERROR_CHECK(attack_lan_init());
    ESP_ERROR_CHECK(sniff_wifi_init());
    ESP_ERROR_CHECK(evil_twin_init());
    ESP_ERROR_CHECK(captive_portal_init());
    ESP_ERROR_CHECK(watchdog_init());
    ESP_ERROR_CHECK(persist_init());
    ESP_ERROR_CHECK(playbook_init());

    while (1) {
        log_mem();
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}
