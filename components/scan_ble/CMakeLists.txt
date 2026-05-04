idf_component_register(
    SRCS "scan_ble.c"
    INCLUDE_DIRS "include"
    REQUIRES protocol bt esp_timer
)
