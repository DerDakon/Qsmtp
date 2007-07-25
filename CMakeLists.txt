PROJECT(Qsmtp)

SET(AUTOQMAIL /var/qmail)

ADD_DEFINITIONS(-O0 -c -Wall -W -Wshadow -Wno-sign-compare -Wno-pointer-sign -DNOSTDERR -DUSESYSLOG -g)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

ADD_SUBDIRECTORY(lib)
ADD_SUBDIRECTORY(qsmtpd)
ADD_SUBDIRECTORY(qremote)
ADD_SUBDIRECTORY(tools)

SET_SOURCE_FILES_PROPERTIES(qremote/qremote.c PROPERTIES COMPILE_FLAGS -DAUTOQMAIL='"${AUTOQMAIL}"')
ADD_EXECUTABLE(Qremote qremote/qremote.c qremote/conn.c qremote/starttlsr.c qremote/qrdata.c)
TARGET_LINK_LIBRARIES(Qremote
	qsmtp_lib
	ssl
	owfat
)

SET_SOURCE_FILES_PROPERTIES(qsmtpd/qsmtpd.c PROPERTIES COMPILE_FLAGS -DAUTOQMAIL='"${AUTOQMAIL}"')
ADD_EXECUTABLE(Qsmtpd qsmtpd/qsmtpd.c qsmtpd/antispam.c qsmtpd/auth.c qsmtpd/starttls.c
		qsmtpd/spf.c qsmtpd/vpop.c qsmtpd/data.c qsmtpd/addrsyntax.c)
TARGET_LINK_LIBRARIES(Qsmtpd
	qsmtp_lib
	rcptfilters
	ssl
	owfat
)

INSTALL(TARGETS Qsmtpd DESTINATION bin)
INSTALL(TARGETS Qremote DESTINATION bin)

SET_SOURCE_FILES_PROPERTIES(tools/fcshell.c PROPERTIES COMPILE_FLAGS --std=c99)

#ADD_EXECUTABLE(fcshell tools/fcshell.c)

SET_SOURCE_FILES_PROPERTIES(tools/qsurvey.c PROPERTIES COMPILE_FLAGS -DAUTOQMAIL='"${AUTOQMAIL}"')
ADD_EXECUTABLE(Qsurvey tools/qsurvey.c qremote/conn.c qremote/starttlsr.c)
TARGET_LINK_LIBRARIES(Qsurvey
	qsmtp_lib
	ssl
	owfat
)
INSTALL(TARGETS Qsurvey DESTINATION bin COMPONENT tools)

ADD_EXECUTABLE(testspf tools/testspf.c qsmtpd/spf.c qsmtpd/antispam.c)
TARGET_LINK_LIBRARIES(testspf
	qsmtp_lib
	ssl
	owfat
)

ADD_EXECUTABLE(qpencode tools/qp.c qremote/qrdata.c)
TARGET_LINK_LIBRARIES(qpencode qsmtp_lib)
ADD_EXECUTABLE(clearpass tools/clearpass.c)
TARGET_LINK_LIBRARIES(clearpass qsmtp_lib)
ADD_EXECUTABLE(addipbl tools/addipbl.c)

INSTALL(TARGETS testspf DESTINATION bin COMPONENT tools)
INSTALL(TARGETS qpencode DESTINATION bin COMPONENT tools)
INSTALL(TARGETS clearpass DESTINATION bin COMPONENT tools)
INSTALL(TARGETS addipbl DESTINATION bin COMPONENT tools)
#INSTALL(TARGETS fcshell DESTINATION bin COMPONENT tools)

#install:
#	install -s -g qmail -o qmaild Qsmtpd $(AUTOQMAIL)/bin
#	install -s -g qmail -o qmailr Qremote $(AUTOQMAIL)/bin

INSTALL(FILES doc/man/Qremote.8 doc/man/Qsmtpd.8 DESTINATION man/man8)
INSTALL(FILES doc/man/filterconf.5 DESTINATION man/man5)

#man-install:
#	install doc/man/Qremote.8 $(AUTOQMAIL)/man/man8
#	install doc/man/Qsmtpd.8 $(AUTOQMAIL)/man/man8
#	install doc/man/filterconf.5 $(AUTOQMAIL)/man/man5
