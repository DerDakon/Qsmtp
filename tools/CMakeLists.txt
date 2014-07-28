SET_SOURCE_FILES_PROPERTIES(fcshell.c PROPERTIES COMPILE_FLAGS --std=c99)

#ADD_EXECUTABLE(fcshell fcshell.c)

ADD_EXECUTABLE(Qsurvey
	qsurvey.c
	${CMAKE_SOURCE_DIR}/qremote/client.c
	${CMAKE_SOURCE_DIR}/qremote/conn.c
	${CMAKE_SOURCE_DIR}/qremote/greeting.c
	${CMAKE_SOURCE_DIR}/qremote/starttlsr.c
	${CMAKE_SOURCE_DIR}/qremote/status.c
)
TARGET_LINK_LIBRARIES(Qsurvey
	qsmtp_lib
	qsmtp_io_lib
	${MEMCHECK_LIBRARIES}
)

INSTALL(TARGETS
		Qsurvey
	DESTINATION bin
	COMPONENT tools
)

ADD_EXECUTABLE(testspf testspf.c ${CMAKE_SOURCE_DIR}/qsmtpd/spf.c ${CMAKE_SOURCE_DIR}/qsmtpd/antispam.c)
TARGET_LINK_LIBRARIES(testspf
	qsmtp_lib
	qsmtp_io_lib
)

ADD_EXECUTABLE(qpencode
	qp.c
	${CMAKE_SOURCE_DIR}/qremote/mime.c
	${CMAKE_SOURCE_DIR}/qremote/qrdata.c
)
TARGET_LINK_LIBRARIES(qpencode
	qsmtp_lib
	qsmtp_io_lib
)

ADD_EXECUTABLE(clearpass clearpass.c)
TARGET_LINK_LIBRARIES(clearpass
	qsmtp_lib
	qsmtp_io_lib
)

ADD_EXECUTABLE(addipbl addipbl.c)

ADD_EXECUTABLE(sendremote sendremote.c)

INCLUDE_DIRECTORIES(
		${OWFAT_INCLUDE_DIRS}
)

INSTALL(TARGETS
		testspf
		qpencode
		clearpass
		addipbl
		sendremote
#		fcshell
	DESTINATION bin
	COMPONENT tools
)
