idf_component_register(
    SRCS "status_led.c"
    INCLUDE_DIRS "include"
    REQUIRES transport_ble scan_wifi scan_ble hacking_wifi hacking_ble
             attack_lan sniff_wifi evil_twin captive_portal watchdog
)
