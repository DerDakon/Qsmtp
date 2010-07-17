SET_SOURCE_FILES_PROPERTIES(qremote.c PROPERTIES COMPILE_FLAGS -DAUTOQMAIL='"${AUTOQMAIL}"')

SET(QREMOTE_SRCS
	qremote.c
	conn.c
	starttlsr.c
	qrdata.c
	smtproutes.c
)

SET(QREMOTE_HDRS
	../include/conn.h
	../include/qrdata.h
	../include/qremote.h
	../include/starttlsr.h
)

ADD_EXECUTABLE(Qremote
	${QREMOTE_SRCS}
	${QREMOTE_HDRS}
)
TARGET_LINK_LIBRARIES(Qremote
	qsmtp_lib
)

INSTALL(TARGETS Qremote DESTINATION bin COMPONENT core)

#install:
#	install -s -g qmail -o qmailr Qremote $(AUTOQMAIL)/bin
