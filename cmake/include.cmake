get_filename_component(libesphttpd_DIR ${CMAKE_CURRENT_LIST_DIR}/.. ABSOLUTE)

set(libesphttpd_SRCS
    ${libesphttpd_DIR}/src/auth.c
    ${libesphttpd_DIR}/src/base64.c
    ${libesphttpd_DIR}/src/captdns.c
    ${libesphttpd_DIR}/src/httpd.c
    ${libesphttpd_DIR}/src/plat_posix.c
    ${libesphttpd_DIR}/src/snprintf.c
    ${libesphttpd_DIR}/src/route_fs.c
    ${libesphttpd_DIR}/src/route_redirect.c
    ${libesphttpd_DIR}/src/sha1.c
    ${libesphttpd_DIR}/src/ws.c
)

set(libesphttpd_INCLUDE_DIRS
    ${libesphttpd_DIR}/include
)

if(CONFIG_IDF_TARGET_ESP8266 OR ESP_PLATFORM)
    set(FREERTOS true)
    set(libesphttpd_SRCS ${libesphttpd_SRCS}
        ${libesphttpd_DIR}/src/esp32_flash.c
        ${libesphttpd_DIR}/src/route_flash.c
        ${libesphttpd_DIR}/src/route_wifi.c
    )
    set(libesphttpd_PRIV_REQUIRES
        app_update
        json
        openssl
        wpa_supplicant
    )
endif()

if(EXISTS ${libesphttpd_DIR}/../libespfs)
    set(libesphttpd_SRCS ${libesphttpd_SRCS}
        ${libesphttpd_DIR}/src/route_espfs.c
    )
    set(libesphttpd_INCLUDE_DIRS ${libesphttpd_INCLUDE_DIRS}
        ${libesphttpd_DIR}/../libespfs/include
    )
endif()

if(FREERTOS)
    set(libesphttpd_SRCS ${libesphttpd_SRCS}
        ${libesphttpd_DIR}/src/port_freertos.c
    )
endif()

if(NOT FREERTOS AND UNIX)
    set(libesphttpd_SRCS ${libesphttpd_SRCS}
        ${libesphttpd_DIR}/src/port_linux.c
    )
endif()

if(NOT ESP_PLATFORM OR NOT EXISTS ${libesphttpd_DIR}/../frozen)
    set(libesphttpd_SRCS ${libesphttpd_SRCS}
        ${libesphttpd_DIR}/third-party/frozen/frozen.c
    )
    set(libesphttpd_INCLUDE_DIRS ${libesphttpd_INCLUDE_DIRS}
        ${libesphttpd_DIR}/third-party/frozen
    )
endif()

function(target_add_resources target)
    foreach(resource ${ARGN})
        if(IS_ABSOLUTE ${resource})
            file(RELATIVE_PATH resource ${PROJECT_SOURCE_DIR} ${resource})
        endif()

        set(output ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/${target}.dir/${resource})
        file(RELATIVE_PATH rel_output ${CMAKE_CURRENT_BINARY_DIR} ${output})

        get_filename_component(dir ${output} DIRECTORY)
        file(MAKE_DIRECTORY ${dir})

        add_custom_command(OUTPUT ${output}.c
            COMMAND ${python} ${libespfs_DIR}/tools/bin2c.py ${resource} ${output}.c
            DEPENDS ${resource}
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            COMMENT "Building source file ${rel_output}.c"
            VERBATIM
        )
        target_sources(${target} PRIVATE ${output}.c)
    endforeach()
endfunction()

function(target_config_vars)
    get_cmake_property(VARS VARIABLES)
    foreach(VAR ${VARS})
        if (VAR MATCHES "^CONFIG_")
            target_compile_definitions(${ARGV0} PUBLIC "-D${VAR}=${${VAR}}")
        endif()
    endforeach()
endfunction()

if(NOT CONFIG_IDF_TARGET_ESP8266 AND NOT ESP_PLATFORM)
    list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})

    if(CONFIG_EHTTPD_TLS_MBEDTLS)
        find_package(MbedTLS)
        if(MBEDTLS_FOUND)
            include_directories(${MBEDTLS_INCLUDE_DIR})
            link_directories(${MBEDTLS_LIBRARIES})
            message(STATUS "Using MbedTLS ${MBEDTLS_VERSION}")
        else()
            message(FATAL_ERROR "MbedTLS not found and CONFIG_EHTTPD_TLS_MBEDTLS selected")
        endif()
    elseif(CONFIG_EHTTPD_TLS_OPENSSL)
        find_package(OpenSSL)
        if(OpenSSL_FOUND)
            include_directories(${OPENSSL_INCLUDE_DIRS})
            link_directories(${OPENSSL_LIBRARIES})
            message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
        else()
            message(FATAL_ERROR "OpenSSL not found and CONFIG_EHTTPD_TLS_OPENSSL selected")
        endif()
    endif()
endif()
