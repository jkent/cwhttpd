get_filename_component(ehttpd_DIR ${CMAKE_CURRENT_LIST_DIR}/.. ABSOLUTE CACHE)

set(ehttpd_SRC
    ${ehttpd_DIR}/src/auth.c
    ${ehttpd_DIR}/src/base64.c
    ${ehttpd_DIR}/src/captdns.c
    ${ehttpd_DIR}/src/httpd.c
    ${ehttpd_DIR}/src/plat_posix.c
    ${ehttpd_DIR}/src/snprintf.c
    ${ehttpd_DIR}/src/route_fs.c
    ${ehttpd_DIR}/src/route_redirect.c
    ${ehttpd_DIR}/src/sha1.c
    ${ehttpd_DIR}/src/ws.c
    ${ehttpd_DIR}/third-party/frozen/frozen.c
)

set(ehttpd_IDF_SRC
    ${ehttpd_DIR}/src/port_freertos.c

    #${ehttpd_DIR}/src/esp32_flash.c
    #${ehttpd_DIR}/src/route_flash.c
    #${ehttpd_DIR}/src/route_wifi.c
)

set(ehttpd_LINUX_SRC
    ${ehttpd_DIR}/src/port_linux.c
)

set(ehttpd_INC
    ${ehttpd_DIR}/include
    ${ehttpd_DIR}/third-party/frozen
)

set(ehttpd_PRIV_REQ
    #app_update
    mbedtls
    spi_flash
    #wpa_supplicant
)
