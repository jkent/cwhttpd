cmake_minimum_required(VERSION 3.5)

include(${CMAKE_CURRENT_LIST_DIR}/cmake/include.cmake)

if(CONFIG_IDF_TARGET_ESP8266 OR ESP_PLATFORM)
    idf_component_register(
        SRCS ${libesphttpd_SRCS}
        INCLUDE_DIRS ${libesphttpd_INCLUDE_DIRS}
        PRIV_REQUIRES ${libesphttpd_PRIV_REQUIRES}
    )
else()
    add_library(libesphttpd STATIC ${libesphttpd_SRCS})
    target_include_directories(libesphttpd PUBLIC ${libesphttpd_INCLUDE_DIRS})
    target_compile_definitions(libesphttpd PUBLIC -DUNIX)
    target_config_vars(libesphttpd)

    install(TARGETS libesphttpd DESTINATION lib)
    install(DIRECTORY include/libesphttpd DESTINATION include)
endif()
