idf_component_register(
    SRCS "scan_wifi.c"
    INCLUDE_DIRS "include"
    REQUIRES protocol esp_wifi esp_event esp_netif esp_timer nvs_flash
)
