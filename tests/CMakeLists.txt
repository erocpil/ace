add_executable(test_sk_buff test_sk_buff.c)
target_include_directories(test_sk_buff PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_options(test_sk_buff PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME sk_buff COMMAND test_sk_buff)

add_executable(test_task_protocol test_task_protocol.c)
target_include_directories(test_task_protocol PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_options(test_task_protocol PRIVATE -Wall -Wextra -Werror -UNDEBUG)
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
	target_compile_options(test_task_protocol PRIVATE -Wno-gnu-variable-sized-type-not-at-end)
endif()
add_test(NAME task_protocol COMMAND test_task_protocol)

add_executable(test_udp_send test_udp_send.c)
target_include_directories(test_udp_send PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_options(test_udp_send PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME udp_send COMMAND test_udp_send)

add_executable(test_io_retry test_io_retry.c)
target_include_directories(test_io_retry PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_options(test_io_retry PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME io_retry COMMAND test_io_retry)

add_executable(test_net_addr test_net_addr.c)
target_include_directories(test_net_addr PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_options(test_net_addr PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME net_addr COMMAND test_net_addr)

add_executable(test_quic_global_concurrency
	test_quic_global_concurrency.c ${PROJECT_SOURCE_DIR}/src/quic_global.c)
target_include_directories(test_quic_global_concurrency PRIVATE
	${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/include/lsquic)
target_compile_options(test_quic_global_concurrency PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_libraries(test_quic_global_concurrency PRIVATE
	-Wl,--start-group liblsquic.a libssl.a libcrypto.a -Wl,--end-group pthread z m)
add_test(NAME quic_global_concurrency COMMAND test_quic_global_concurrency)

add_test(
	NAME build_deps_version_selection
	COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/check-build-deps.sh
		${PROJECT_SOURCE_DIR}/scripts/build-deps.sh)

add_test(
	NAME smoke_test_safety
	COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/check-smoke-test.sh
		${PROJECT_SOURCE_DIR}/scripts/smoke-test.sh)

add_test(
	NAME no_process_exit
	COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/check-no-process-exit.sh
		${PROJECT_SOURCE_DIR})

add_test(
	NAME loop_ownership
	COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/check-loop-ownership.sh
		${PROJECT_SOURCE_DIR}/src/runner.c)

add_test(
	NAME failure_observability
	COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/check-observability.sh
		${PROJECT_SOURCE_DIR})

add_test(
	NAME task_ownership
	COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/check-task-ownership.sh
		${PROJECT_SOURCE_DIR}/src/task.c)

add_test(
	NAME quic_global_lifecycle
	COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/check-quic-global.sh
		${PROJECT_SOURCE_DIR})

add_test(
	NAME ephemeral_test_certificates
	COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/check-test-certificates.sh
		${PROJECT_SOURCE_DIR})

add_test(
	NAME fault_injection_contract
	COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/check-fault-injection.sh
		${PROJECT_SOURCE_DIR})

if(ACE_BUILD_FUZZERS)
	if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
		message(FATAL_ERROR "ACE_BUILD_FUZZERS requires Clang")
	endif()
	add_executable(fuzz_task_protocol fuzz_task_protocol.c)
	target_include_directories(fuzz_task_protocol PRIVATE ${PROJECT_SOURCE_DIR}/src)
	target_compile_options(fuzz_task_protocol PRIVATE -fsanitize=fuzzer,address -fno-omit-frame-pointer)
	target_link_options(fuzz_task_protocol PRIVATE -fsanitize=fuzzer,address)
endif()
