cmake_minimum_required(VERSION 3.16)

project(ace)

set(ACE_SANITIZER "" CACHE STRING "Enable address, undefined, or leak sanitizer")
set_property(CACHE ACE_SANITIZER PROPERTY STRINGS "" address undefined leak)
option(ACE_BUILD_FUZZERS "Build libFuzzer protocol targets (Clang only)" OFF)

if(ACE_SANITIZER)
	if(NOT ACE_SANITIZER MATCHES "^(address|undefined|leak)$")
		message(FATAL_ERROR "Unsupported ACE_SANITIZER=${ACE_SANITIZER}")
	endif()
	add_compile_options(-fsanitize=${ACE_SANITIZER} -fno-omit-frame-pointer)
	add_link_options(-fsanitize=${ACE_SANITIZER})
endif()

include(CTest)

add_definitions(-g -O0 -Wall -Wextra -fno-omit-frame-pointer -Wno-comment)
# add_definitions(-O1 -Wall -Wextra -fno-omit-frame-pointer -Wno-comment)
add_definitions(-Wno-unused-value -Wno-unused-variable -Wno-unused-function -Wno-strict-aliasing -Wno-unused-parameter -Wno-unused-result)
add_definitions(-DLSQUIC_DEBUG_NEXT_ADV_TICK=1 -DLSQUIC_CONN_STATS=1)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include/)
include_directories(${PROJECT_SOURCE_DIR}/include/libev/)
include_directories(${PROJECT_SOURCE_DIR}/include/lsquic/)
include_directories(${PROJECT_SOURCE_DIR}/include/file/)

if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64.*|AARCH64.*|arm64.*|ARM64.*)")
	link_directories(${PROJECT_SOURCE_DIR}/lib/aarch64/)
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
	link_directories(${PROJECT_SOURCE_DIR}/lib/x86_64/)
else ()
	message(FATAL_ERROR "Detected processor: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

link_directories(${CMAKE_CURRENT_BINARY_DIR})

include(CheckGit.cmake)
CheckGitSetup()

include (Auth.cmake)

function(CheckCpuFreq)
	execute_process (
		COMMAND bash -c "lscpu | grep -P 'CPU (max )?MHz:' | grep -oP '(?<= )[1-9].+$'"
		WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
		OUTPUT_VARIABLE FREQ
		OUTPUT_STRIP_TRAILING_WHITESPACE
		ERROR_QUIET
	)
	message(STATUS "CPU MHz: " ${FREQ})
	add_compile_definitions(MHz=${FREQ})
endfunction()
CheckCpuFreq()

# add_compile_definitions(MHz=100.001)

add_subdirectory(src)

if (BUILD_TESTING)
	add_subdirectory(tests)
endif()
