ADD_SUBDIRECTORY(filters)

SET_SOURCE_FILES_PROPERTIES(qsmtpd.c PROPERTIES COMPILE_FLAGS -DAUTOQMAIL='"${AUTOQMAIL}"')

SET(QSMTPD_SRCS
	qsmtpd.c
	antispam.c
	auth.c
	starttls.c
	spf.c
	vpop.c
	data.c
	addrsyntax.c
)

SET(QSMTPD_HDRS
	../include/antispam.h
	../include/qsauth.h
	../include/qsdata.h
	../include/qsmtpd.h
	../include/userfilters.h
	../include/vpop.h
)

ADD_EXECUTABLE(Qsmtpd
	${QSMTPD_SRCS}
	${QSMTPD_HDRS}
)

TARGET_LINK_LIBRARIES(Qsmtpd
	qsmtp_lib
	rcptfilters
	${MEMCHECK_LIBRARIES}
)

INSTALL(TARGETS Qsmtpd DESTINATION bin COMPONENT core)

#install:
#	install -s -g qmail -o qmaild Qsmtpd $(AUTOQMAIL)/bin
