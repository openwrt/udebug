cmake_minimum_required(VERSION 3.13)

PROJECT(udebugd C)

ADD_DEFINITIONS(-O2 -Wall -fwrapv -Werror --std=gnu99 -g3 -Wmissing-declarations -DRUNSTATEDIR="${RUNSTATEDIR}")
FIND_LIBRARY(ubus NAMES ubus)
FIND_LIBRARY(ubox NAMES ubox)

FIND_PATH(ubus_include_dir NAMES libubus.h)
FIND_PATH(uloop_include_dir NAMES libubox/uloop.h)
FIND_PATH(ucode_include_dir NAMES ucode/module.h)
INCLUDE_DIRECTORIES(${uloop_include_dir} ${ubus_include_dir} ${ucode_include_dir})

IF(APPLE)
  SET(UCODE_MODULE_LINK_OPTIONS "LINKER:-undefined,dynamic_lookup")
ENDIF()

ADD_LIBRARY(udebug SHARED lib.c lib-pcap.c)
IF(ABIVERSION)
  SET_TARGET_PROPERTIES(udebug PROPERTIES VERSION ${ABIVERSION})
ENDIF()
TARGET_LINK_LIBRARIES(udebug ${ubox} ${ubus})

ADD_EXECUTABLE(udebugd main.c client.c ring.c ubus.c)
TARGET_LINK_LIBRARIES(udebugd udebug ${ubox} ${ubus})

ADD_LIBRARY(ucode_lib MODULE lib-ucode.c)
SET_TARGET_PROPERTIES(ucode_lib PROPERTIES OUTPUT_NAME udebug PREFIX "")
TARGET_LINK_OPTIONS(ucode_lib PRIVATE ${UCODE_MODULE_LINK_OPTIONS})
TARGET_LINK_LIBRARIES(ucode_lib ${ubox} udebug)

INSTALL(FILES udebug.h udebug-pcap.h
	DESTINATION include
)
INSTALL(FILES udebug-cli
	DESTINATION sbin
	RENAME udebug
)
INSTALL(TARGETS udebugd udebug
	RUNTIME DESTINATION sbin
	LIBRARY DESTINATION lib
)
INSTALL(TARGETS ucode_lib
	LIBRARY DESTINATION lib/ucode
)

ADD_CUSTOM_TARGET(debian
	COMMAND ${CMAKE_COMMAND} -E echo "Generating debian/changelog from git..."
	COMMAND ${CMAKE_SOURCE_DIR}/debian/generate-changelog.sh
	COMMAND dpkg-buildpackage -b -uc -us
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	COMMENT "Building Debian package"
)
