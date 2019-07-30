include (ExternalProject)
include (ExternalSource)
include (BuildSupport)

if (NOT liblz_core_NAME)

external_git_repo (liblz_core
    HEAD
    git@github.com:dnsdrop/liblz_core.git)

ExternalProject_Add(${liblz_core_NAME}
        PREFIX            ${BUILDEM_DIR}
        GIT_REPOSITORY    ${liblz_core_URL}
        GIT_TAG           ${liblz_core_TAG}
        UPDATE_COMMAND    ""
        BUILD_IN_SOURCE 1
        TEST_COMMAND      ""
        CONFIGURE_COMMAND ${BUILDEM_ENV_STR} ${CMAKE_COMMAND} ${liblz_core_SRC_DIR}
            -DCMAKE_EXE_LINKER_FLAGS=-L${BUILDEM_LIB_DIR}
            -DCMAKE_INSTALL_PREFIX:PATH=${BUILDEM_DIR}
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
)

endif()
