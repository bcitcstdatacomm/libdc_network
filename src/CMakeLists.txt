# Note that headers are optional, and do not affect add_library, but they will not
# show up in IDEs unless they are listed in add_library.

add_definitions(-D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)

if (APPLE)
    add_definitions(-D_DARWIN_C_SOURCE -D__APPLE_USE_RFC_3542)
endif ()

set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*,-llvmlibc-restrict-system-libc-headers,-cppcoreguidelines-init-variables,-clang-analyzer-security.insecureAPI.strcpy,-concurrency-mt-unsafe,-android-cloexec-accept,-android-cloexec-dup,-google-readability-todo,-cppcoreguidelines-avoid-magic-numbers,-readability-magic-numbers,-cert-dcl03-c,-hicpp-static-assert,-misc-static-assert,-altera-struct-pack-align,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling;--quiet")

# Make a shared library
add_library(dc_network SHARED ${SOURCE_LIST} ${HEADER_LIST})
target_include_directories(dc_network PRIVATE ../include/dc_network)
target_include_directories(dc_network PRIVATE /usr/include)
target_include_directories(dc_network PRIVATE /usr/local/include)
target_link_directories(dc_network PRIVATE /usr/lib)
target_link_directories(dc_network PRIVATE /usr/local/lib)

set_target_properties(dc_network PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR})

# All users of this library will need at least C11
target_compile_features(dc_network PUBLIC c_std_11)
target_compile_options(dc_network PRIVATE -g -fPIC)
target_compile_options(dc_network PRIVATE -fstack-protector-all -ftrapv)
target_compile_options(dc_network PRIVATE -Wpedantic -Wall -Wextra)
target_compile_options(dc_network PRIVATE -Wdouble-promotion -Wformat-nonliteral -Wformat-security -Wformat-y2k -Wnull-dereference -Winit-self -Wmissing-include-dirs -Wswitch-default -Wswitch-enum -Wunused-local-typedefs -Wstrict-overflow=5 -Wmissing-noreturn -Walloca -Wfloat-equal -Wdeclaration-after-statement -Wshadow -Wpointer-arith -Wabsolute-value -Wundef -Wexpansion-to-defined -Wunused-macros -Wno-endif-labels -Wbad-function-cast -Wcast-qual -Wwrite-strings -Wconversion -Wdangling-else -Wdate-time -Wempty-body -Wsign-conversion -Wfloat-conversion -Waggregate-return -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-declarations -Wpacked -Wredundant-decls -Wnested-externs -Winline -Winvalid-pch -Wlong-long -Wvariadic-macros -Wdisabled-optimization -Wstack-protector -Woverlength-strings)

find_library(LIBM m REQUIRED)
if (LIBM)
    target_link_libraries(dc_network ${LIBM})
endif ()

find_library(LIBDC_POSIX dc_posix REQUIRED)
if (LIBDC_POSIX)
    target_link_libraries(dc_network ${LIBDC_POSIX})
endif ()

find_library(LIBDC_FSM dc_fsm REQUIRED)
if (LIBDC_FSM)
    target_link_libraries(dc_network ${LIBDC_FSM})
endif ()

install(TARGETS dc_network LIBRARY DESTINATION lib)
install(FILES ${HEADER_LIST} DESTINATION include/dc_network)

# IDEs should put the headers in a nice place
source_group(
        TREE "${PROJECT_SOURCE_DIR}/include"
        PREFIX "Header Files"
        FILES ${HEADER_LIST}
)

add_custom_target(
        format
        COMMAND clang-format
        -i
        ${HEADER_LIST}
        ${SOURCE_LIST}
)
