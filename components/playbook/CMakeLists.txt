idf_component_register(
    SRCS "playbook.c"
    INCLUDE_DIRS "include"
    REQUIRES protocol transport_ble command_router json esp_timer
)
