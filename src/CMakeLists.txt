add_executable(ace
	ace.c server.c client.c service.c connote.c config.c upstream.c task.c runner.c quic_global.c tls_context.c )
add_dependencies(ace auth)
target_compile_definitions(ace PRIVATE
	ACE_DEFAULT_CERT_FILE="${cert}"
	ACE_DEFAULT_KEY_FILE="${pkey}")
target_link_libraries(ace dl -Wl,--start-group liblsquic.a libssl.a libcrypto.a -Wl,--end-group libev.a libmagic.so liblzma.so m pthread z git_version)

add_executable(alpha alpha.c upstream.c)
target_link_libraries(alpha dl libev.a m pthread z git_version)
