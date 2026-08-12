set(cert "${CMAKE_CURRENT_BINARY_DIR}/cert.pem")
set(pkey "${CMAKE_CURRENT_BINARY_DIR}/rsa_private.key")
find_program(_OPENSSL openssl)
add_custom_command(
	OUTPUT "${cert}" "${pkey}"
	WORKING_DIRECTORY
	${CMAKE_CURRENT_BINARY_DIR}
	COMMENT
	"generating Certificate and Private key"
	PRE_BUILD
	COMMAND ${_OPENSSL}
	ARGS req -newkey rsa:2048 -nodes -keyout "${pkey}" -x509 -days 365 -out "${cert}" -subj '/'
)
add_custom_target(auth DEPENDS "${cert}" "${pkey}")
