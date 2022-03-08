include(${CMAKE_CURRENT_LIST_DIR}/files.cmake)

idf_component_register(
SRCS
    ${ehttpd_SRC}
    ${ehttpd_IDF_SRC}
INCLUDE_DIRS
    ${ehttpd_INC}
PRIV_REQUIRES
    ${ehttpd_PRIV_REQ}
)

if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/../../frogfs)
    include(${CMAKE_CURRENT_LIST_DIR}/../../frogfs/cmake/files.cmake)

    target_sources(${COMPONENT_LIB}
    PUBLIC
        ${frogfs_SRC}
        ${frogfs_IDF_SRC}
        ${frogfs_ehttpd_SRC}
    )
    target_include_directories(${COMPONENT_LIB}
    PUBLIC
        ${frogfs_INC}
        ${frogfs_ehttpd_INC}
    )
endif()
