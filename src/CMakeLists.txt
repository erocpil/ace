add_executable(ace
	ace.c server.c client.c service.c connote.c config.c upstream.c task.c runner.c )
target_link_libraries(ace dl -Wl,--start-group liblsquic.a libssl.a libcrypto.a -Wl,--end-group libev.a libmagic.so liblzma.so m pthread z git_version)

add_executable(alpha alpha.c upstream.c)
target_link_libraries(alpha dl libev.a m pthread z git_version)
