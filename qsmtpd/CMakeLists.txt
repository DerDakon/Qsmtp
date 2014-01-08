ADD_SUBDIRECTORY(filters)

ADD_LIBRARY(Qsmtpd_auth_checkpassword STATIC
	qsauth_backend_cp.c
)

TARGET_LINK_LIBRARIES(Qsmtpd_auth_checkpassword
	qsmtp_io_lib
	${MEMCHECK_LIBRARIES}
)

SET(QSMTPD_SRCS
	addrparse.c
	addrsyntax.c
	antispam.c
	auth.c
	getfile.c
	qsmtpd.c
	starttls.c
	spf.c
	vpop.c
	data.c
	syntax.c
	xtext.c
)

SET(QSMTPD_HDRS
	../include/qsmtpd/addrparse.h
	../include/qsmtpd/antispam.h
	../include/qsmtpd/qsauth.h
	../include/qsmtpd/qsauth_backend.h
	../include/qsmtpd/qsdata.h
	../include/qsmtpd/qsmtpd.h
	../include/qsmtpd/syntax.h
	../include/qsmtpd/userfilters.h
	../include/qsmtpd/vpop.h
)

ADD_EXECUTABLE(Qsmtpd
	${QSMTPD_SRCS}
	${QSMTPD_HDRS}
)

TARGET_LINK_LIBRARIES(Qsmtpd
	qsmtp_lib
	qsmtp_io_lib
	rcptfilters
	Qsmtpd_auth_checkpassword
	${MEMCHECK_LIBRARIES}
)

INSTALL(TARGETS Qsmtpd DESTINATION bin COMPONENT core)

#install:
#	install -s -g qmail -o qmaild Qsmtpd $(AUTOQMAIL)/bin
