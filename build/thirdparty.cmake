set (BUILDEM_DIR "None" CACHE TYPE STRING)

if (${BUILDEM_DIR} STREQUAL "None")
    set (BUILDEM_DIR ${CMAKE_BINARY_DIR})
endif()

set  (BUILDEM_REPO_DIR ${BUILDEM_DIR}/src/buildem)
list (APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
list (APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/thirdparty")

include(libevent)
include(libevhtp)
include(libldns)
include(liblz_core)
include(liblz_json)

add_custom_target(AppDependencies ALL
    DEPENDS ${APP_DEPENDENCIES}
    COMMENT "Installed third-party deps")
