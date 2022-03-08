include(${CMAKE_CURRENT_LIST_DIR}/files.cmake)

function(target_add_resource target path)
    if(IS_ABSOLUTE ${path})
        set(input ${path})
    else()
        set(input ${CMAKE_CURRENT_SOURCE_DIR}/${path})
    endif()
    file(RELATIVE_PATH rel_input ${CMAKE_CURRENT_SOURCE_DIR} ${input})
    set(output ${CMAKE_CURRENT_BINARY_DIR}/${rel_input})
    get_filename_component(dir ${output} DIRECTORY)

    add_custom_command(OUTPUT ${output}.c
        COMMAND ${CMAKE_COMMAND} -E make_directory ${dir}
        COMMAND ${python} ${ehttpd_DIR}/tools/bin2c.py ${input} ${output}.c
        DEPENDS ${resource}
        COMMENT "Building source file for ${rel_input}"
        VERBATIM
    )
    target_sources(${target} PRIVATE ${output}.c)
endfunction()