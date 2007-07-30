ADD_SUBDIRECTORY(filters)

SET_SOURCE_FILES_PROPERTIES(qsmtpd.c PROPERTIES COMPILE_FLAGS -DAUTOQMAIL='"${AUTOQMAIL}"')
ADD_EXECUTABLE(Qsmtpd
	qsmtpd.c
	antispam.c
	auth.c
	starttls.c
	spf.c
	vpop.c
	data.c
	addrsyntax.c
)
TARGET_LINK_LIBRARIES(Qsmtpd
	qsmtp_lib
	rcptfilters
	ssl
	owfat
)

INSTALL(TARGETS Qsmtpd DESTINATION bin COMPONENT core)

#install:
#	install -s -g qmail -o qmaild Qsmtpd $(AUTOQMAIL)/bin
