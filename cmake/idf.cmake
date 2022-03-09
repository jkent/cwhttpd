include(${CMAKE_CURRENT_LIST_DIR}/files.cmake)

idf_component_register(
SRCS
    ${cwhttpd_SRC}
    ${cwhttpd_IDF_SRC}
INCLUDE_DIRS
    ${cwhttpd_INC}
PRIV_REQUIRES
    ${cwhttpd_IDF_PRIV_REQ}
)

if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/../../frogfs)
    include(${CMAKE_CURRENT_LIST_DIR}/../../frogfs/cmake/files.cmake)

    target_sources(${COMPONENT_LIB}
    PUBLIC
        ${frogfs_SRC}
        ${frogfs_IDF_SRC}
        ${frogfs_cwhttpd_SRC}
    )
    target_include_directories(${COMPONENT_LIB}
    PUBLIC
        ${frogfs_INC}
        ${frogfs_cwhttpd_INC}
    )
endif()
