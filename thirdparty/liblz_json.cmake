include (ExternalProject)
include (ExternalSource)
include (BuildSupport)

if (NOT liblz_json_NAME)

external_git_repo (liblz_json
    master
    git@github.com:dnsdrop/liblz_json.git)

ExternalProject_Add(${liblz_json_NAME}
        DEPENDS           ${liblz_core_NAME}
        PREFIX            ${BUILDEM_DIR}
        GIT_REPOSITORY    ${liblz_json_URL}
        GIT_TAG           ${liblz_json_TAG}
        UPDATE_COMMAND    ""
        BUILD_IN_SOURCE 1
        TEST_COMMAND      ""
        CONFIGURE_COMMAND ${BUILDEM_ENV_STR} ${CMAKE_COMMAND} ${liblz_json_SRC_DIR}
            -DCMAKE_EXE_LINKER_FLAGS=-L${BUILDEM_LIB_DIR}
            -DCMAKE_INSTALL_PREFIX:PATH=${BUILDEM_DIR}
            -DCMAKE_PREFIX_PATH=${BUILDEM_DIR}
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DLZ_JSON_OMIT_EMPTY=On

)

endif()
