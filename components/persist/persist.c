#include "persist.h"

#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "nvs.h"

static const char *TAG = "persist";

#define NVS_NAMESPACE  "wifiutils"
// NVS key length max 15 chars. Prefix "p_" + name (≤14 chars) excederia,
// então usamos só o name direto. Names devem ter ≤15 chars.

esp_err_t persist_init(void)
{
    // NVS já é inicializado pelo transport_ble; aqui só abrimos o
    // namespace pra confirmar que é válido. Retorna se outra coisa
    // já consumiu o partition.
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err == ESP_OK) {
        nvs_close(h);
        ESP_LOGI(TAG, "ready (namespace='%s')", NVS_NAMESPACE);
        return ESP_OK;
    }
    ESP_LOGW(TAG, "nvs_open rc=%s — profiles persistirão se NVS for inicializado", esp_err_to_name(err));
    return ESP_OK;
}

static bool name_valid(const char *name)
{
    if (!name) return false;
    size_t len = strnlen(name, PERSIST_PROFILE_NAME_MAX + 2);
    if (len == 0 || len > PERSIST_PROFILE_NAME_MAX) return false;
    // NVS keys: caracteres ASCII printable, sem espaço/null
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (c < 0x21 || c > 0x7E) return false;
    }
    return true;
}

esp_err_t persist_profile_save(const char *name, const char *data, size_t data_len)
{
    if (!name_valid(name) || !data) return ESP_ERR_INVALID_ARG;
    if (data_len == 0 || data_len > PERSIST_PROFILE_MAX_BYTES) return ESP_ERR_INVALID_ARG;

    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "save: nvs_open rc=%s", esp_err_to_name(err));
        return err;
    }
    err = nvs_set_blob(h, name, data, data_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "save: set_blob rc=%s", esp_err_to_name(err));
        nvs_close(h);
        return err;
    }
    err = nvs_commit(h);
    nvs_close(h);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "save: '%s' (%u bytes)", name, (unsigned)data_len);
    }
    return err;
}

esp_err_t persist_profile_load(const char *name, char *out, size_t out_cap, size_t *out_len)
{
    if (!name_valid(name) || !out || out_cap == 0) return ESP_ERR_INVALID_ARG;

    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) return err;

    size_t blob_len = 0;
    err = nvs_get_blob(h, name, NULL, &blob_len);
    if (err != ESP_OK) {
        nvs_close(h);
        return err;
    }
    if (blob_len > out_cap) {
        nvs_close(h);
        return ESP_ERR_INVALID_SIZE;
    }
    err = nvs_get_blob(h, name, out, &blob_len);
    nvs_close(h);
    if (err == ESP_OK && out_len) *out_len = blob_len;
    return err;
}

esp_err_t persist_profile_delete(const char *name)
{
    if (!name_valid(name)) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_erase_key(h, name);
    if (err == ESP_OK) nvs_commit(h);
    nvs_close(h);
    if (err == ESP_OK) ESP_LOGI(TAG, "delete: '%s'", name);
    return err;
}

esp_err_t persist_profile_list(char out_names[][PERSIST_PROFILE_NAME_MAX + 1],
                                size_t cap, size_t *out_count)
{
    if (!out_names || cap == 0 || !out_count) return ESP_ERR_INVALID_ARG;
    *out_count = 0;

    nvs_iterator_t it = NULL;
    esp_err_t err = nvs_entry_find(NVS_DEFAULT_PART_NAME, NVS_NAMESPACE,
                                     NVS_TYPE_BLOB, &it);
    while (err == ESP_OK && it && *out_count < cap) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);
        size_t klen = strnlen(info.key, sizeof(info.key));
        if (klen <= PERSIST_PROFILE_NAME_MAX) {
            memcpy(out_names[*out_count], info.key, klen);
            out_names[*out_count][klen] = 0;
            (*out_count)++;
        }
        err = nvs_entry_next(&it);
    }
    if (it) nvs_release_iterator(it);
    return ESP_OK;
}
