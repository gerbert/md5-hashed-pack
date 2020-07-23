cmake_minimum_required (VERSION 2.6)

project (md5-hashed-pack)

# The version number.
SET(APP_VERSION_MAJOR 0)
SET(APP_VERSION_MINOR 1)
SET(APP_VERSION_REVISION 2)

include_directories("${PROJECT_SOURCE_DIR}/include")
include_directories("${PROJECT_SOURCE_DIR}/src")

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
   "${PROJECT_SOURCE_DIR}/config.h.in"
   "${PROJECT_SOURCE_DIR}/include/config.h"
)

SET(EXTRA_LIBS ssl crypto)

# add the executable
add_executable(md5-hashed-pack src/pack.c)
target_link_libraries(md5-hashed-pack ${EXTRA_LIBS})
INSTALL(TARGETS md5-hashed-pack DESTINATION bin)

# build a CPack driven installer package
include (InstallRequiredSystemLibraries)

SET(CPACK_GENERATOR "DEB")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Hashed container storage for user files")
SET(CPACK_PACKAGE_VENDOR "Andrei Andreyanau")
SET(CPACK_PACKAGE_VERSION_MAJOR ${APP_VERSION_MAJOR})
SET(CPACK_PACKAGE_VERSION_MINOR ${APP_VERSION_MINOR})
SET(CPACK_PACKAGE_VERSION_PATCH ${APP_VERSION_REVISION})
SET(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl1.1 (>=1.1.0f-3+deb9u1), libmbedcrypto0 (>=2.4.2-1+deb9u1)")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Andrei Andreyanau")
SET(CPACK_STRIP_FILES "bin/md5-hashed-pack")

include (CPack)
