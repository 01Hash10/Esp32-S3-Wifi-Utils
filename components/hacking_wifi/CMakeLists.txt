idf_component_register(
    SRCS "hacking_wifi.c" "wsl_bypasser.c"
    INCLUDE_DIRS "include"
    REQUIRES protocol transport_ble esp_wifi esp_timer esp_event wpa_supplicant
)
# wsl_bypasser.c traz override de `ieee80211_raw_frame_sanity_check`. Para
# o linker pegar nossa versão em vez da do `libnet80211.a`, o flag
# `-Wl,--weaken-symbol=ieee80211_raw_frame_sanity_check` está em
# `platformio.ini > build_flags` (mais simples que --wrap, que falhava
# silenciosamente em IDF 5.4).
#
# Pré-requisito: ESP-IDF 5.1.x ou inferior. Em 5.2+ a Espressif adicionou
# um filter mais cedo no caminho TX (`unsupport frame type 0c0`) que roda
# ANTES desta função — nesse caso o bypass não alcança e só patch binário
# do libnet80211.a resolveria. Pinamos em 5.1.2 via espressif32 @ 6.5.0.
