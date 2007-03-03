PROJECT(Qsmtp)

SET(AUTOQMAIL /var/qmail)
SET(CMAKE_INSTALL_PREFIX ${AUTOQMAIL})

ADD_DEFINITIONS(-O0 -c -Wall -W -Wshadow -Wno-sign-compare -Wno-pointer-sign -DNOSTDERR -DUSESYSLOG -g)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

ADD_SUBDIRECTORY(lib)
ADD_SUBDIRECTORY(qsmtpd)
ADD_SUBDIRECTORY(qremote)
ADD_SUBDIRECTORY(tools)

SET_SOURCE_FILES_PROPERTIES(qremote/qremote.c PROPERTIES COMPILE_FLAGS -DAUTOQMAIL='"${AUTOQMAIL}"')
ADD_EXECUTABLE(targets/Qremote qremote/qremote.c qremote/conn.c qremote/starttlsr.c qremote/qrdata.c)
TARGET_LINK_LIBRARIES(targets/Qremote dns netio ssl_timeoutio log tls control match mime
			libowfatconn ssl crypto owfat)

SET_SOURCE_FILES_PROPERTIES(qsmtpd/qsmtpd.c PROPERTIES COMPILE_FLAGS -DAUTOQMAIL='"${AUTOQMAIL}"')
ADD_EXECUTABLE(targets/Qsmtpd qsmtpd/qsmtpd.c qsmtpd/antispam.c qsmtpd/auth.c qsmtpd/starttls.c
		qsmtpd/spf.c qsmtpd/vpop.c qsmtpd/data.c qsmtpd/addrsyntax.c)
TARGET_LINK_LIBRARIES(targets/Qsmtpd dns control getfile ssl_timeoutio tls base64 match
			log netio libowfatconn cdb xtext ssl crypto owfat rcptfilters)

INSTALL(TARGETS targets/Qsmtpd DESTINATION bin)
INSTALL(TARGETS targets/Qremote DESTINATION bin)

SET_SOURCE_FILES_PROPERTIES(tools/fcshell.c PROPERTIES COMPILE_FLAGS --std=c99)

#ADD_EXECUTABLE(targets/fcshell tools/fcshell.c)

SET_SOURCE_FILES_PROPERTIES(tools/qsurvey.c PROPERTIES COMPILE_FLAGS -DAUTOQMAIL='"${AUTOQMAIL}"')
ADD_EXECUTABLE(targets/Qsurvey tools/qsurvey.c qremote/conn.c qremote/starttlsr.c)
TARGET_LINK_LIBRARIES(targets/Qsurvey dns netio ssl_timeoutio log tls control match libowfatconn ssl crypto owfat)
INSTALL(TARGETS targets/Qsurvey DESTINATION bin COMPONENT tools)

ADD_EXECUTABLE(targets/testspf tools/testspf.c qsmtpd/spf.c qsmtpd/antispam.c)
TARGET_LINK_LIBRARIES(targets/testspf dns match netio tls ssl_timeoutio libowfatconn ssl crypto owfat)

ADD_EXECUTABLE(targets/qpencode tools/qp.c qremote/qrdata.c)
TARGET_LINK_LIBRARIES(targets/qpencode mime)
ADD_EXECUTABLE(targets/clearpass tools/clearpass.c)
TARGET_LINK_LIBRARIES(targets/clearpass base64)
ADD_EXECUTABLE(targets/addipbl tools/addipbl.c)

INSTALL(TARGETS targets/testspf DESTINATION bin COMPONENT tools)
INSTALL(TARGETS targets/qpencode DESTINATION bin COMPONENT tools)
INSTALL(TARGETS targets/clearpass DESTINATION bin COMPONENT tools)
INSTALL(TARGETS targets/addipbl DESTINATION bin COMPONENT tools)
#INSTALL(TARGETS targets/fcshell DESTINATION bin COMPONENT tools)

#install:
#	install -s -g qmail -o qmaild targets/Qsmtpd $(AUTOQMAIL)/bin
#	install -s -g qmail -o qmailr targets/Qremote $(AUTOQMAIL)/bin

#man-install:
#	install doc/man/Qremote.8 $(AUTOQMAIL)/man/man8
#	install doc/man/Qsmtpd.8 $(AUTOQMAIL)/man/man8
#	install doc/man/filterconf.5 $(AUTOQMAIL)/man/man5
