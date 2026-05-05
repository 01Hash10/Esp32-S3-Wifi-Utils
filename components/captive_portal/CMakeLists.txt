idf_component_register(
    SRCS "captive_portal.c"
    INCLUDE_DIRS "include"
    REQUIRES protocol transport_ble lwip esp_netif
)
