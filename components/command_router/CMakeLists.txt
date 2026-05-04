idf_component_register(
    SRCS "command_router.c"
    INCLUDE_DIRS "include"
    REQUIRES protocol transport_ble scan_wifi json esp_timer esp_app_format
)
