idf_component_register(
    SRCS "transport_ble.c"
    INCLUDE_DIRS "include"
    REQUIRES protocol bt nvs_flash esp_timer
)
