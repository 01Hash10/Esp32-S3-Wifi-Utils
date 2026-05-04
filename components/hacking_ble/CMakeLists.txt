idf_component_register(
    SRCS "hacking_ble.c"
    INCLUDE_DIRS "include"
    REQUIRES protocol bt esp_timer transport_ble
)
