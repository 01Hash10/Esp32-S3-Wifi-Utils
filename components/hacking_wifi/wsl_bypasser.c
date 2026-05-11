// wsl_bypasser — override de `ieee80211_raw_frame_sanity_check` para
// permitir injection de frames mgmt arbitrários via `esp_wifi_80211_tx`.
//
// Origem: GANESH-ICMC/esp32-deauther → risinek/esp32-wifi-penetration-tool
// (`components/wsl_bypasser/wsl_bypasser.c`).
//
// Como funciona: o driver Wi-Fi do ESP-IDF chama
// `ieee80211_raw_frame_sanity_check(arg1, arg2, arg3)` antes de aceitar
// um frame em `esp_wifi_80211_tx`. A função (em `libnet80211.a`,
// blob fechado) retorna 0 pra frames "bem comportados" e -1 pra mgmt
// frames como deauth (0xC0) que normalmente seriam dropados.
//
// Trick: declarar `__wrap_ieee80211_raw_frame_sanity_check` aqui
// retornando sempre 0 e adicionar `-Wl,--wrap=ieee80211_raw_frame_sanity_check`
// no link (ver platformio.ini). O linker redireciona chamadas a
// `ieee80211_raw_frame_sanity_check` (do libnet80211.a) pra nossa
// `__wrap_…` — bypass total da validação.
//
// Funciona até ESP-IDF 5.1.x. A partir de 5.2 a Espressif adicionou
// outro filter mais cedo (mensagem `unsupport frame type 0c0`) que
// roda ANTES desta função — nesse caso só patch binário do libnet80211.a
// resolveria. Pinamos em 5.1.2 (espressif32 @ 6.5.0) por isso.

#include <stdint.h>

int __wrap_ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3)
{
    (void)arg; (void)arg2; (void)arg3;
    return 0;
}
