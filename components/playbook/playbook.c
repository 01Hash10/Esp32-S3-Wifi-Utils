#include "playbook.h"
#include "tlv.h"
#include "transport_ble.h"
#include "command_router.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "playbook";

#define PB_MAX_STEPS    32
#define PB_MAX_VARS     8
#define PB_VAR_NAME_MAX 16
#define PB_VAR_VALUE_MAX 64

typedef enum {
    PB_STEP_CMD,
    PB_STEP_WAIT_MS,
    PB_STEP_WAIT_EVENT,
    PB_STEP_SET,
} pb_step_type_t;

typedef struct {
    char name[PB_VAR_NAME_MAX + 1];
    char value[PB_VAR_VALUE_MAX + 1];
    bool used;
} pb_var_t;

static volatile bool s_active = false;
static volatile bool s_stop_req = false;
static TaskHandle_t s_task = NULL;
static char *s_steps_json = NULL;
static pb_var_t s_vars[PB_MAX_VARS];
static uint8_t s_seq = 0;

// Estado do wait_event
static volatile uint8_t s_wait_event_msg_type = 0xFF;  // 0xFF = não esperando
static volatile bool s_wait_event_seen = false;

bool playbook_busy(void) { return s_active; }

esp_err_t playbook_init(void)
{
    ESP_LOGI(TAG, "ready");
    return ESP_OK;
}

// Hook strong override do hook weak em transport_ble.c — chamado a cada
// envio de TLV no stream. Notifica wait_event se msg_type bater.
void playbook_hook_tlv(uint8_t msg_type, const uint8_t *payload, size_t len)
{
    (void)payload; (void)len;
    if (!s_active) return;
    if (s_wait_event_msg_type == msg_type) {
        s_wait_event_seen = true;
    }
}

// ----------------------------------------------------------------------
// TLVs
// ----------------------------------------------------------------------

static void emit_step_done(uint16_t step_idx, uint8_t step_type, uint8_t status)
{
    uint8_t payload[4];
    payload[0] = (uint8_t)(step_idx >> 8);
    payload[1] = (uint8_t)(step_idx & 0xFF);
    payload[2] = step_type;
    payload[3] = status;

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_PLAYBOOK_STEP_DONE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

static void emit_done(uint16_t total_steps, uint16_t completed,
                       uint8_t status, uint32_t elapsed_ms)
{
    uint8_t payload[9];
    payload[0] = (uint8_t)(total_steps >> 8); payload[1] = (uint8_t)(total_steps & 0xFF);
    payload[2] = (uint8_t)(completed >> 8);   payload[3] = (uint8_t)(completed & 0xFF);
    payload[4] = status;
    payload[5] = (uint8_t)(elapsed_ms >> 24); payload[6] = (uint8_t)(elapsed_ms >> 16);
    payload[7] = (uint8_t)(elapsed_ms >> 8);  payload[8] = (uint8_t)(elapsed_ms & 0xFF);

    uint8_t out[TLV_MAX_FRAME_SIZE];
    int total = tlv_encode(out, sizeof(out),
                           TLV_MSG_PLAYBOOK_DONE, s_seq++,
                           payload, sizeof(payload));
    if (total > 0) transport_ble_send_stream(out, (size_t)total);
}

// ----------------------------------------------------------------------
// Variável: lookup + substituição
// ----------------------------------------------------------------------

static const char *var_get(const char *name)
{
    for (int i = 0; i < PB_MAX_VARS; i++) {
        if (s_vars[i].used && strcmp(s_vars[i].name, name) == 0) {
            return s_vars[i].value;
        }
    }
    return NULL;
}

static void var_set(const char *name, const char *value)
{
    // memcpy + null explícito — IDF 5.1.x exige -Wstringop-truncation safe.
    // Helper local: copia até `max` bytes e termina null no índice `max`.
    // Update existente?
    for (int i = 0; i < PB_MAX_VARS; i++) {
        if (s_vars[i].used && strcmp(s_vars[i].name, name) == 0) {
            size_t vl = strnlen(value, PB_VAR_VALUE_MAX);
            memcpy(s_vars[i].value, value, vl);
            s_vars[i].value[vl] = 0;
            return;
        }
    }
    // Slot livre
    for (int i = 0; i < PB_MAX_VARS; i++) {
        if (!s_vars[i].used) {
            size_t nl = strnlen(name, PB_VAR_NAME_MAX);
            memcpy(s_vars[i].name, name, nl);
            s_vars[i].name[nl] = 0;
            size_t vl = strnlen(value, PB_VAR_VALUE_MAX);
            memcpy(s_vars[i].value, value, vl);
            s_vars[i].value[vl] = 0;
            s_vars[i].used = true;
            return;
        }
    }
    ESP_LOGW(TAG, "var slots cheios — '%s' descartada", name);
}

// Recursivamente substitui strings com prefixo "$" no JSON tree.
static void json_substitute_vars(cJSON *node)
{
    if (!node) return;
    if (cJSON_IsString(node)) {
        const char *s = node->valuestring;
        if (s && s[0] == '$') {
            const char *replacement = var_get(s);
            if (replacement) {
                cJSON_SetValuestring(node, replacement);
            }
        }
        return;
    }
    cJSON *child = node->child;
    while (child) {
        json_substitute_vars(child);
        child = child->next;
    }
}

// ----------------------------------------------------------------------
// Step execution
// ----------------------------------------------------------------------

// Retorna 0 = ok, 1 = falha, 2 = stop
static int exec_step_cmd(cJSON *step)
{
    cJSON *cmd_j = cJSON_GetObjectItemCaseSensitive(step, "cmd");
    if (!cJSON_IsString(cmd_j) || !cmd_j->valuestring[0]) {
        ESP_LOGW(TAG, "step cmd: missing 'cmd' field");
        return 1;
    }
    cJSON *args_j = cJSON_GetObjectItemCaseSensitive(step, "args");

    // Monta novo JSON: { "cmd":"X", "seq":-1, ...args }
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "cmd", cmd_j->valuestring);
    cJSON_AddNumberToObject(root, "seq", -1);
    if (cJSON_IsObject(args_j)) {
        cJSON *child = args_j->child;
        while (child) {
            cJSON *dup = cJSON_Duplicate(child, 1);
            cJSON_AddItemToObject(root, child->string, dup);
            child = child->next;
        }
    }

    // Substitui variáveis
    json_substitute_vars(root);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) return 1;

    // Despacha pelo command_router (no contexto da playbook task)
    command_router_handle_json((const uint8_t *)json_str, strlen(json_str));
    cJSON_free(json_str);
    return 0;
}

static int exec_step_wait_ms(cJSON *step)
{
    cJSON *ms_j = cJSON_GetObjectItemCaseSensitive(step, "ms");
    int ms = cJSON_IsNumber(ms_j) ? ms_j->valueint : 0;
    if (ms < 0)      ms = 0;
    if (ms > 600000) ms = 600000;

    int64_t deadline = esp_timer_get_time() + (int64_t)ms * 1000;
    while (!s_stop_req && esp_timer_get_time() < deadline) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    return s_stop_req ? 2 : 0;
}

static int exec_step_wait_event(cJSON *step)
{
    cJSON *tlv_j = cJSON_GetObjectItemCaseSensitive(step, "tlv");
    cJSON *to_j  = cJSON_GetObjectItemCaseSensitive(step, "timeout_ms");
    if (!cJSON_IsNumber(tlv_j)) return 1;

    int target = tlv_j->valueint;
    if (target < 0 || target > 0xFF) return 1;
    int timeout = cJSON_IsNumber(to_j) ? to_j->valueint : 30000;
    if (timeout < 100)    timeout = 100;
    if (timeout > 600000) timeout = 600000;

    s_wait_event_msg_type = (uint8_t)target;
    s_wait_event_seen = false;

    int64_t deadline = esp_timer_get_time() + (int64_t)timeout * 1000;
    while (!s_stop_req && !s_wait_event_seen &&
           esp_timer_get_time() < deadline) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    s_wait_event_msg_type = 0xFF;
    if (s_stop_req) return 2;
    return s_wait_event_seen ? 0 : 1;
}

static int exec_step_set(cJSON *step)
{
    cJSON *name_j = cJSON_GetObjectItemCaseSensitive(step, "name");
    cJSON *val_j  = cJSON_GetObjectItemCaseSensitive(step, "value");
    if (!cJSON_IsString(name_j) || !name_j->valuestring[0]) return 1;

    const char *name = name_j->valuestring;
    char vbuf[PB_VAR_VALUE_MAX + 1];
    if (cJSON_IsString(val_j)) {
        strncpy(vbuf, val_j->valuestring, PB_VAR_VALUE_MAX);
        vbuf[PB_VAR_VALUE_MAX] = 0;
    } else if (cJSON_IsNumber(val_j)) {
        snprintf(vbuf, sizeof(vbuf), "%g", val_j->valuedouble);
    } else {
        return 1;
    }
    var_set(name, vbuf);
    return 0;
}

// Identifica step type. Retorna -1 se inválido.
static int step_type_from_str(const char *type)
{
    if (!type) return -1;
    if (strcmp(type, "cmd") == 0)        return PB_STEP_CMD;
    if (strcmp(type, "wait_ms") == 0)    return PB_STEP_WAIT_MS;
    if (strcmp(type, "wait_event") == 0) return PB_STEP_WAIT_EVENT;
    if (strcmp(type, "set") == 0)        return PB_STEP_SET;
    return -1;
}

static void playbook_task(void *arg)
{
    (void)arg;
    int64_t start_us = esp_timer_get_time();

    cJSON *root = cJSON_Parse(s_steps_json);
    if (!root) {
        ESP_LOGE(TAG, "json parse failed");
        emit_done(0, 0, 2, 0);
        goto cleanup;
    }

    // Aceita tanto array direto quanto {"steps":[...]}
    cJSON *steps_arr = cJSON_IsArray(root) ? root :
                        cJSON_GetObjectItemCaseSensitive(root, "steps");
    if (!cJSON_IsArray(steps_arr)) {
        ESP_LOGE(TAG, "json não é array de steps");
        cJSON_Delete(root);
        emit_done(0, 0, 2, 0);
        goto cleanup;
    }

    int total = cJSON_GetArraySize(steps_arr);
    if (total > PB_MAX_STEPS) total = PB_MAX_STEPS;

    int completed = 0;
    int errors = 0;

    for (int i = 0; i < total && !s_stop_req; i++) {
        cJSON *step = cJSON_GetArrayItem(steps_arr, i);
        cJSON *type_j = cJSON_GetObjectItemCaseSensitive(step, "type");
        int type = cJSON_IsString(type_j) ?
                    step_type_from_str(type_j->valuestring) : -1;
        if (type < 0) {
            ESP_LOGW(TAG, "step %d: type inválido", i);
            emit_step_done((uint16_t)i, 0xFF, 1);
            errors++;
            if (errors >= 3) break; // abort em 3 erros consecutivos
            continue;
        }

        int rc = 1;
        switch (type) {
        case PB_STEP_CMD:        rc = exec_step_cmd(step); break;
        case PB_STEP_WAIT_MS:    rc = exec_step_wait_ms(step); break;
        case PB_STEP_WAIT_EVENT: rc = exec_step_wait_event(step); break;
        case PB_STEP_SET:        rc = exec_step_set(step); break;
        }

        emit_step_done((uint16_t)i, (uint8_t)type, (uint8_t)rc);
        if (rc == 0) {
            completed++;
            errors = 0;
        } else if (rc == 2) {
            break; // stop request
        } else {
            errors++;
            if (errors >= 3) {
                ESP_LOGW(TAG, "abort: 3 erros consecutivos");
                break;
            }
        }
    }

    cJSON_Delete(root);

    uint32_t elapsed = (uint32_t)((esp_timer_get_time() - start_us) / 1000);
    uint8_t status = s_stop_req ? 2 : (errors >= 3 ? 1 : 0);
    emit_done((uint16_t)total, (uint16_t)completed, status, elapsed);
    ESP_LOGI(TAG, "playbook done: %d/%d steps in %u ms (status=%u)",
             completed, total, (unsigned)elapsed, (unsigned)status);

cleanup:
    free(s_steps_json);
    s_steps_json = NULL;
    // Limpa vars
    for (int i = 0; i < PB_MAX_VARS; i++) s_vars[i].used = false;
    s_stop_req = false;
    s_active = false;
    s_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t playbook_run(const char *steps_json)
{
    if (s_active) return ESP_ERR_INVALID_STATE;
    if (!steps_json || !steps_json[0]) return ESP_ERR_INVALID_ARG;

    size_t len = strlen(steps_json);
    if (len > 4096) return ESP_ERR_INVALID_SIZE;

    s_steps_json = malloc(len + 1);
    if (!s_steps_json) return ESP_ERR_NO_MEM;
    memcpy(s_steps_json, steps_json, len + 1);

    for (int i = 0; i < PB_MAX_VARS; i++) s_vars[i].used = false;
    s_stop_req = false;
    s_active = true;

    if (xTaskCreate(playbook_task, "playbook", 6144, NULL, 5, &s_task) != pdPASS) {
        free(s_steps_json);
        s_steps_json = NULL;
        s_active = false;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "started: %u bytes JSON", (unsigned)len);
    return ESP_OK;
}

esp_err_t playbook_stop(void)
{
    if (!s_active) return ESP_ERR_INVALID_STATE;
    s_stop_req = true;
    return ESP_OK;
}
