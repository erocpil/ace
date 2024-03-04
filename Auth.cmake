set(cert "cert.pem")
set(pkey "rsa_private.key")
find_program(_OPENSSL openssl)
add_custom_command(
	OUTPUT AUTH
	WORKING_DIRECTORY
	${CMAKE_CURRENT_BINARY_DIR}
	COMMENT
	"generating Certificate and Private key"
	PRE_BUILD
	COMMAND ${_OPENSSL}
	ARGS req -newkey rsa:2048 -nodes -keyout "${pkey}" -x509 -days 365 -out "${cert}" -subj '/'
)
add_custom_target(auth DEPENDS AUTH)
