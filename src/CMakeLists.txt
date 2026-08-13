add_executable(ace
	ace.c server.c client.c service.c connote.c config.c upstream.c task_dispatch.c task_sendfile.c task_perf.c runner.c quic_global.c tls_context.c tls_identity.c protocol_codec.c quic_connection.c quic_stream.c quic_engine.c quic_session.c mem_budget.c packet_io.c control_command.c control_socket.c )
add_dependencies(ace auth)
target_compile_definitions(ace PRIVATE
	ACE_DEFAULT_CERT_FILE="${cert}"
	ACE_DEFAULT_KEY_FILE="${pkey}")
target_link_libraries(ace dl -Wl,--start-group liblsquic.a libssl.a libcrypto.a -Wl,--end-group libev.a libmagic.so liblzma.so m pthread z git_version)

add_executable(alpha alpha.c upstream.c mem_budget.c control_socket.c control_command.c)
target_link_libraries(alpha dl libev.a m pthread z git_version)
