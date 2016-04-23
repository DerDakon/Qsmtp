option(QREMOTE_PEDANTIC_STATUS_CODES "Be pedantic about the status codes Qremote accepts from remote servers" OFF)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/statuscodes.h.tmpl ${CMAKE_CURRENT_BINARY_DIR}/statuscodes.h @ONLY)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(QREMOTE_SRCS
	common_setup.c
	envelope.c
	greeting.c
	qremote.c
	client.c
	conn.c
	conn_mx.c
	mime.c
	qrdata.c
	reply.c
	smtproutes.c
	starttlsr.c
	status.c
)

set(QREMOTE_HDRS
	../include/qremote/client.h
	../include/qremote/conn.h
	../include/qremote/mime.h
	../include/qremote/greeting.h
	../include/qremote/qrdata.h
	../include/qremote/qremote.h
	../include/qremote/starttlsr.h
)

if(CHUNKING)
	list(APPEND QREMOTE_SRCS
			qrbdat.c
	)
endif()

add_executable(Qremote
	${QREMOTE_SRCS}
	${QREMOTE_HDRS}
)
target_link_libraries(Qremote
	qsmtp_lib
	qsmtp_io_lib
	qsmtp_dane_lib
	${MEMCHECK_LIBRARIES}
	${OPENSSL_LIBRARIES}
)

install(TARGETS Qremote DESTINATION bin COMPONENT core)

#install:
#	install -s -g qmail -o qmailr Qremote $(AUTOQMAIL)/bin
