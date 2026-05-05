idf_component_register(
    SRCS "sniff_wifi.c"
    INCLUDE_DIRS "include"
    REQUIRES protocol transport_ble esp_wifi esp_timer
)
