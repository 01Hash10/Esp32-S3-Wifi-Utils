idf_component_register(
    SRCS "command_router.c"
    INCLUDE_DIRS "include"
    REQUIRES protocol transport_ble scan_wifi scan_ble hacking_wifi hacking_ble attack_lan sniff_wifi evil_twin captive_portal json esp_timer esp_app_format
)
