PROJECT(Qs_auth_chkpw C)

ADD_LIBRARY(Qsmtpd_auth_checkpassword STATIC
	qsauth_backend_cp.c
)

TARGET_LINK_LIBRARIES(Qsmtpd_auth_checkpassword
	${MEMCHECK_LIBRARIES}
)
