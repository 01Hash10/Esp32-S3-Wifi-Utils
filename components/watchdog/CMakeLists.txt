idf_component_register(
    SRCS "watchdog.c"
    INCLUDE_DIRS "include"
    REQUIRES protocol transport_ble hacking_wifi hacking_ble esp_timer
)
