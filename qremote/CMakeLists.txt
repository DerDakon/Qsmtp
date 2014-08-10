OPTION(QREMOTE_PEDANTIC_STATUS_CODES "Be pedantic about the status codes Qremote accepts from remote servers" OFF)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/statuscodes.h.tmpl ${CMAKE_CURRENT_BINARY_DIR}/statuscodes.h @ONLY)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})

SET(QREMOTE_SRCS
	greeting.c
	qremote.c
	client.c
	conn.c
	conn_mx.c
	mime.c
	qrdata.c
	smtproutes.c
	starttlsr.c
	status.c
)

SET(QREMOTE_HDRS
	../include/qremote/client.h
	../include/qremote/conn.h
	../include/qremote/mime.h
	../include/qremote/greeting.h
	../include/qremote/qrdata.h
	../include/qremote/qremote.h
	../include/qremote/starttlsr.h
)

IF(CHUNKING)
	LIST(APPEND QREMOTE_SRCS
			qrbdat.c
	)
ENDIF()

ADD_EXECUTABLE(Qremote
	${QREMOTE_SRCS}
	${QREMOTE_HDRS}
)
TARGET_LINK_LIBRARIES(Qremote
	qsmtp_lib
	qsmtp_io_lib
	qsmtp_dane_lib
	${MEMCHECK_LIBRARIES}
	${OPENSSL_LIBRARIES}
)

INSTALL(TARGETS Qremote DESTINATION bin COMPONENT core)

#install:
#	install -s -g qmail -o qmailr Qremote $(AUTOQMAIL)/bin
