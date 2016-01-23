project(Qs_auth_chkpw C)

add_library(Qsmtpd_auth_checkpassword STATIC
	qsauth_backend_cp.c
)

target_link_libraries(Qsmtpd_auth_checkpassword
	${MEMCHECK_LIBRARIES}
)
