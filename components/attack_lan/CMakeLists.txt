idf_component_register(
    SRCS "attack_lan.c"
    INCLUDE_DIRS "include"
    REQUIRES protocol transport_ble esp_wifi esp_event esp_netif esp_timer lwip
)
