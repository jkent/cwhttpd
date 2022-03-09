include(${CMAKE_CURRENT_LIST_DIR}/files.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../../frogfs/cmake/files.cmake)

add_library(cwhttpd
    ${cwhttpd_SRC}
    ${cwhttpd_LINUX_SRC}
)

target_compile_definitions(cwhttpd PRIVATE UNIX)

target_include_directories(cwhttpd
PUBLIC
    ${cwhttpd_INC}
PRIVATE
    ${cwhttpd_PRIV_INC}
)

if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/../../frogfs)
    include(${CMAKE_CURRENT_LIST_DIR}/../../frogfs/cmake/files.cmake)

    target_sources(cwhttpd
    PUBLIC
        ${frogfs_SRC}
        ${frogfs_cwhttpd_SRC}
    )
    target_include_directories(cwhttpd
    PUBLIC
        ${frogfs_INC}
        ${frogfs_PRIV_INC}
    )
endif()
