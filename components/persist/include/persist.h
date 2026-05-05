#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

esp_err_t persist_init(void);

// Profile = JSON blob nomeado (string com NUL terminator), armazenado
// no NVS namespace "wifiutils". Usado pra salvar workflows / configs
// que app/playbook engine podem recall depois.
//
// Limites:
//   - name: 1..14 chars (limit do NVS keys = 15 menos prefix interno)
//   - content: até PERSIST_PROFILE_MAX_BYTES bytes
//   - máximo de profiles armazenados: limitado pela partition NVS (4KB
//     da partição "nvs" → ~50–100 profiles dependendo do tamanho)

#define PERSIST_PROFILE_MAX_BYTES   1024  // teto generoso; cabe vários TLVs fragmentados se preciso depois
#define PERSIST_PROFILE_NAME_MAX    14
#define PERSIST_PROFILE_LIST_MAX    32     // max profiles listados de uma vez

esp_err_t persist_profile_save(const char *name, const char *data, size_t data_len);
esp_err_t persist_profile_load(const char *name, char *out, size_t out_cap, size_t *out_len);
esp_err_t persist_profile_delete(const char *name);

// Retorna até `cap` nomes em `out_names[i]` (cada um com até NAME_MAX+1
// chars). `*out_count` recebe quantos foram preenchidos.
esp_err_t persist_profile_list(char out_names[][PERSIST_PROFILE_NAME_MAX + 1],
                                size_t cap, size_t *out_count);
