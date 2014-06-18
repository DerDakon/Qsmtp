ADD_SUBDIRECTORY(filters)
ADD_SUBDIRECTORY(backends)

SET(QSMTPD_SRCS
	addrparse.c
	addrsyntax.c
	antispam.c
	auth.c
	child.c
	queue.c
	qsmtpd.c
	starttls.c
	spf.c
	data.c
	syntax.c
	xtext.c
)

SET(QSMTPD_HDRS
	../include/qsmtpd/addrparse.h
	../include/qsmtpd/antispam.h
	../include/qsmtpd/queue.h
	../include/qsmtpd/qsauth.h
	../include/qsmtpd/qsauth_backend.h
	../include/qsmtpd/qsdata.h
	../include/qsmtpd/qsmtpd.h
	../include/qsmtpd/syntax.h
	../include/qsmtpd/userfilters.h
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
	Qsmtpd_user_vpopm
	${MEMCHECK_LIBRARIES}
)

INSTALL(TARGETS Qsmtpd DESTINATION bin COMPONENT core)

#install:
#	install -s -g qmail -o qmaild Qsmtpd $(AUTOQMAIL)/bin
