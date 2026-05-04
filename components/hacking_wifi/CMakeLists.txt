idf_component_register(
    SRCS "hacking_wifi.c"
    INCLUDE_DIRS "include"
    REQUIRES protocol esp_wifi
)
# Nota: tentamos `--wrap=ieee80211_raw_frame_sanity_check` para passar mais
# frames, mas o blob libnet80211 do IDF 5.4 faz setup de TX dentro dessa
# função além da validação — bypassar quebra a TX silenciosamente
# (esp_wifi_80211_tx retorna OK mas o frame não vai pro ar). Sem o wrap,
# só ~10–20 frames passam por chamada, o que ainda é útil em rajadas curtas.
