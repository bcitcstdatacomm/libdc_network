# Note that headers are optional, and do not affect add_library, but they will not
# show up in IDEs unless they are listed in add_library.

set(HEADER_LIST
        "${libdc_network_SOURCE_DIR}/include/dc_network/client.h"
        "${libdc_network_SOURCE_DIR}/include/dc_network/common.h"
        "${libdc_network_SOURCE_DIR}/include/dc_network/options.h"
        "${libdc_network_SOURCE_DIR}/include/dc_network/server.h"
        )

set(SOURCE_LIST
    client.c
	common.c
    options.c
    server.c
        )

# Make an static library
add_library(dc_network SHARED ${SOURCE_LIST} ${HEADER_LIST})
target_include_directories(dc_network PRIVATE ../include/dc_network)
target_include_directories(dc_network PRIVATE /usr/local/include)
target_link_directories(dc_network PRIVATE /usr/local/lib)

set_target_properties(dc_network PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR})

find_library(LIBM m REQUIRED)
if(LIBM)
    target_link_libraries(dc_network ${LIBM})
endif()

find_library(LIBDC_POSIX dc_posix REQUIRED)
if(LIBDC_POSIX)
    target_link_libraries(dc_network ${LIBDC_POSIX})
endif()

find_library(LIBDC_FSM dc_fsm REQUIRED)
if(LIBDC_FSM)
    target_link_libraries(dc_network ${LIBDC_FSM})
endif()

# All users of this library will need at least C11
target_compile_features(dc_network PUBLIC c_std_11)
target_compile_options(dc_network PRIVATE -g -fPIC)
target_compile_options(dc_network PRIVATE -fstack-protector-all -ftrapv)
target_compile_options(dc_network PRIVATE -Wpedantic -Wall -Wextra)
target_compile_options(dc_network PRIVATE -Wdouble-promotion -Wformat-nonliteral -Wformat-security -Wformat-y2k -Wnull-dereference -Winit-self -Wmissing-include-dirs -Wswitch-default -Wswitch-enum -Wunused-local-typedefs -Wstrict-overflow=5 -Wmissing-noreturn -Walloca -Wfloat-equal -Wdeclaration-after-statement -Wshadow -Wpointer-arith -Wabsolute-value -Wundef -Wexpansion-to-defined -Wunused-macros -Wno-endif-labels -Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings -Wconversion -Wdangling-else -Wdate-time -Wempty-body -Wsign-conversion -Wfloat-conversion -Waggregate-return -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-declarations -Wpacked -Wpadded -Wredundant-decls -Wnested-externs -Winline -Winvalid-pch -Wlong-long -Wvariadic-macros -Wdisabled-optimization -Wstack-protector -Woverlength-strings )

install(TARGETS dc_network LIBRARY DESTINATION lib)
install(FILES ${HEADER_LIST} DESTINATION include/dc_network)

# IDEs should put the headers in a nice place
source_group(
        TREE "${PROJECT_SOURCE_DIR}/include"
        PREFIX "Header Files"
        FILES ${HEADER_LIST}
)
