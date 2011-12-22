OPTION(QREMOTE_PEDANTIC_STATUS_CODES "Be pedantic about the status codes Qremote accepts from remote servers" OFF)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/statuscodes.h.tmpl ${CMAKE_CURRENT_BINARY_DIR}/statuscodes.h @ONLY)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})

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
	qsmtp_io_lib
	${MEMCHECK_LIBRARIES}
)

INSTALL(TARGETS Qremote DESTINATION bin COMPONENT core)

#install:
#	install -s -g qmail -o qmailr Qremote $(AUTOQMAIL)/bin
