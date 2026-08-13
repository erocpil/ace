# -Wno-unused-function is appended AFTER -Werror on every target because
# the ACE headers (sk_buff.h, hash.h, service.h, ...) expose header-local
# static helpers that a test TU may include without calling.  gcc honors the
# top-level add_definitions(-Wno-unused-function); clang is last-wins, so the
# flag must come after -Wall/-Wextra/-Werror to take effect under -Werror.

add_executable(test_sk_buff test_sk_buff.c ${PROJECT_SOURCE_DIR}/src/mem_budget.c)
target_include_directories(test_sk_buff PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_options(test_sk_buff PRIVATE -Wall -Wextra -Werror -Wno-unused-function -UNDEBUG)
add_test(NAME sk_buff COMMAND test_sk_buff)

add_executable(test_task_protocol test_task_protocol.c ${PROJECT_SOURCE_DIR}/src/protocol_codec.c)
target_include_directories(test_task_protocol PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_options(test_task_protocol PRIVATE -Wall -Wextra -Werror -Wno-unused-function -UNDEBUG)
if(CMAKE_C_COMPILER_ID MATCHES "GNU")
	target_compile_options(test_task_protocol PRIVATE -Wno-stringop-overflow)
endif()
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
	target_compile_options(test_task_protocol PRIVATE -Wno-gnu-variable-sized-type-not-at-end)
endif()
add_test(NAME task_protocol COMMAND test_task_protocol)

add_executable(test_protocol_codec test_protocol_codec.c ${PROJECT_SOURCE_DIR}/src/protocol_codec.c)
target_include_directories(test_protocol_codec PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_options(test_protocol_codec PRIVATE -Wall -Wextra -Werror -Wno-unused-function -UNDEBUG)
add_test(NAME protocol_codec COMMAND test_protocol_codec)

add_executable(test_udp_send test_udp_send.c)
target_include_directories(test_udp_send PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_options(test_udp_send PRIVATE -Wall -Wextra -Werror -Wno-unused-function -UNDEBUG)
add_test(NAME udp_send COMMAND test_udp_send)

add_executable(test_io_retry test_io_retry.c)
target_include_directories(test_io_retry PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_options(test_io_retry PRIVATE -Wall -Wextra -Werror -Wno-unused-function -UNDEBUG)
add_test(NAME io_retry COMMAND test_io_retry)

add_executable(test_net_addr test_net_addr.c)
target_include_directories(test_net_addr PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_options(test_net_addr PRIVATE -Wall -Wextra -Werror -Wno-unused-function -UNDEBUG)
add_test(NAME net_addr COMMAND test_net_addr)

add_executable(test_quic_connection test_quic_connection.c ${PROJECT_SOURCE_DIR}/src/quic_connection.c)
target_include_directories(test_quic_connection PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_options(test_quic_connection PRIVATE -Wall -Wextra -Werror -Wno-unused-function -UNDEBUG)
add_test(NAME quic_connection COMMAND test_quic_connection)

add_executable(test_mem_budget unit/test_mem_budget.c ${PROJECT_SOURCE_DIR}/src/mem_budget.c)
target_include_directories(test_mem_budget PRIVATE
	${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/tests/unit)
target_compile_options(test_mem_budget PRIVATE -Wall -Wextra -Werror -Wno-unused-function -UNDEBUG)
add_test(NAME mem_budget COMMAND test_mem_budget)

add_executable(test_quic_global_concurrency
	test_quic_global_concurrency.c ${PROJECT_SOURCE_DIR}/src/quic_global.c)
target_include_directories(test_quic_global_concurrency PRIVATE
	${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/include/lsquic)
target_compile_options(test_quic_global_concurrency PRIVATE -Wall -Wextra -Werror -Wno-unused-function -UNDEBUG)
target_link_libraries(test_quic_global_concurrency PRIVATE
	-Wl,--start-group liblsquic.a libssl.a libcrypto.a -Wl,--end-group pthread z m)
add_test(NAME quic_global_concurrency COMMAND test_quic_global_concurrency)

add_executable(test_packet_io
	test_packet_io.c ${PROJECT_SOURCE_DIR}/src/connote.c ${PROJECT_SOURCE_DIR}/src/packet_io.c ${PROJECT_SOURCE_DIR}/src/mem_budget.c)
target_include_directories(test_packet_io PRIVATE
	${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/include/lsquic ${CMAKE_BINARY_DIR}/generated)
target_compile_options(test_packet_io PRIVATE -Wall -Wextra -Werror -Wno-unused-function -UNDEBUG)
target_link_libraries(test_packet_io PRIVATE
	-Wl,--start-group liblsquic.a libssl.a libcrypto.a -Wl,--end-group pthread z m)
add_test(NAME packet_io COMMAND test_packet_io)

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

add_test(
	NAME tls_identity_verification
	COMMAND bash ${PROJECT_SOURCE_DIR}/scripts/tls-verify-test.sh)
set_tests_properties(tls_identity_verification PROPERTIES
	ENVIRONMENT "ACE_BUILD_DIR=${CMAKE_BINARY_DIR}"
	LABELS integration)

add_test(
	NAME queue_saturation_contract
	COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/check-queue-saturation.sh
		${PROJECT_SOURCE_DIR})

add_test(
	NAME peer_abort_contract
	COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/check-peer-abort.sh
		${PROJECT_SOURCE_DIR})

add_test(
	NAME connection_isolation
	COMMAND bash ${PROJECT_SOURCE_DIR}/scripts/connection-isolation-test.sh)
set_tests_properties(connection_isolation PROPERTIES
	ENVIRONMENT "ACE_BUILD_DIR=${CMAKE_BINARY_DIR}"
	LABELS integration)

if(ACE_BUILD_FUZZERS)
	if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
		message(FATAL_ERROR "ACE_BUILD_FUZZERS requires Clang")
	endif()
	add_executable(fuzz_task_protocol fuzz_task_protocol.c ${PROJECT_SOURCE_DIR}/src/protocol_codec.c)
	target_include_directories(fuzz_task_protocol PRIVATE ${PROJECT_SOURCE_DIR}/src)
	target_compile_options(fuzz_task_protocol PRIVATE -fsanitize=fuzzer,address -fno-omit-frame-pointer)
	target_link_options(fuzz_task_protocol PRIVATE -fsanitize=fuzzer,address)
endif()
