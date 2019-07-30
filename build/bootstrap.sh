#!/usr/bin/env bash

BASEURL="https://raw.githubusercontent.com/NathanFrench/buildem"
BRANCH="master"
OUTDIR="../thirdparty"

mkdir $OUTDIR 2>/dev/null
mkdir ../cmake 2>/dev/null

curl $BASEURL/$BRANCH/BuildSupport.cmake > ../cmake/BuildSupport.cmake
curl $BASEURL/$BRANCH/ExternalSource.cmake > ../cmake/ExternalSource.cmake

cat > thirdparty.cmake << EOL
set (BUILDEM_DIR "None" CACHE TYPE STRING)

if (\${BUILDEM_DIR} STREQUAL "None")
    set (BUILDEM_DIR \${CMAKE_BINARY_DIR})
endif()

set  (BUILDEM_REPO_DIR \${BUILDEM_DIR}/src/buildem)
list (APPEND CMAKE_MODULE_PATH "\${PROJECT_SOURCE_DIR}/cmake")
list (APPEND CMAKE_MODULE_PATH "\${PROJECT_SOURCE_DIR}/thirdparty")
EOL


cat ./DEPS | while read package
do
    curl $BASEURL/$BRANCH/$package.cmake > $OUTDIR/$package.cmake
    echo "include($package)" >> thirdparty.cmake
done

cat >> thirdparty.cmake << EOL
add_custom_target(AppDependencies ALL
    DEPENDS \${APP_DEPENDENCIES}
    COMMENT "Installed third-party deps")
EOL
