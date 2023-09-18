get_filename_component(cwhttpd_DIR ${CMAKE_CURRENT_LIST_DIR}/.. ABSOLUTE CACHE)

set(cwhttpd_SRC
    ${cwhttpd_DIR}/src/auth.c
    ${cwhttpd_DIR}/src/base64.c
    ${cwhttpd_DIR}/src/captdns.c
    ${cwhttpd_DIR}/src/httpd.c
    ${cwhttpd_DIR}/src/plat_posix.c
    ${cwhttpd_DIR}/src/snprintf.c
    ${cwhttpd_DIR}/src/route_fs.c
    ${cwhttpd_DIR}/src/route_redirect.c
    ${cwhttpd_DIR}/src/sha1.c
    ${cwhttpd_DIR}/src/ws.c
)

set(cwhttpd_IDF_SRC
    ${cwhttpd_DIR}/src/port_freertos.c
)

set(cwhttpd_LINUX_SRC
    ${cwhttpd_DIR}/src/port_linux.c
)

set(cwhttpd_INC
    ${cwhttpd_DIR}/include
)

set(cwhttpd_IDF_PRIV_REQ
    freertos
    mbedtls
    esp_netif
)
