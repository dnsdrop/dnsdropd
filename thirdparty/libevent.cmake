include (ExternalProject)
include (ExternalSource)
include (BuildSupport)

if (NOT libevent_NAME)

external_git_repo (libevent
    HEAD
    http://www.github.com/libevent/libevent)

ExternalProject_Add(${libevent_NAME}
        PREFIX            ${BUILDEM_DIR}
        GIT_REPOSITORY    ${libevent_URL}
        GIT_TAG           ${libevent_TAG}
        UPDATE_COMMAND    ""
        TEST_COMMAND      ""
        BUILD_IN_SOURCE   1
        PATCH_COMMAND     "./autogen.sh"
        CONFIGURE_COMMAND ${BUILDEM_ENV_STR}
            ./configure --prefix=${BUILDEM_DIR}
            --disable-libevent-regress
            --disable-debug-mode
            --disable-samples
            --disable-shared
            --enable-static

       BUILD_COMMAND     ${BUILDEM_ENV_STRING} make
       INSTALL_COMMAND   ${BUILDEM_ENV_STRING} make install
)

endif()
