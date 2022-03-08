include(${CMAKE_CURRENT_LIST_DIR}/files.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../../frogfs/cmake/files.cmake)

add_library(ehttpd
    ${ehttpd_SRC}
    ${ehttpd_LINUX_SRC}
    ${frogfs_SRC}
)

target_compile_definitions(ehttpd PRIVATE UNIX)

target_include_directories(ehttpd
PUBLIC
    ${ehttpd_INC}
PRIVATE
    ${ehttpd_PRIV_INC}
)

if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/../../frogfs)
    include(${CMAKE_CURRENT_LIST_DIR}/../../frogfs/cmake/files.cmake)

    target_sources(ehttpd
    PUBLIC
        ${frogfs_SRC}
        ${frogfs_ehttpd_SRC}
    )
    target_include_directories(ehttpd
    PUBLIC
        ${frogfs_INC}
        ${frogfs_PRIV_INC}
    )
endif()
