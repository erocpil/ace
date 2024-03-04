add_executable(ace
	ace.c server.c client.c service.c connote.c config.c upstream.c task.c )
target_link_libraries(ace dl liblsquic.a libssl.a libcrypto.a libev.a libmagic.so liblzma.so m pthread z git_version)

add_executable(alpha alpha.c upstream.c)
target_link_libraries(alpha dl libev.a m pthread z git_version)
