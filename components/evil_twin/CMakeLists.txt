idf_component_register(
    SRCS "evil_twin.c"
    INCLUDE_DIRS "include"
    REQUIRES protocol transport_ble esp_wifi esp_event esp_netif
)
