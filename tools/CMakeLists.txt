SET_SOURCE_FILES_PROPERTIES(fcshell.c PROPERTIES COMPILE_FLAGS --std=c99)

#ADD_EXECUTABLE(fcshell fcshell.c)

SET_SOURCE_FILES_PROPERTIES(qsurvey.c PROPERTIES COMPILE_FLAGS -DAUTOQMAIL='"${AUTOQMAIL}"')
ADD_EXECUTABLE(Qsurvey
	qsurvey.c
	${CMAKE_SOURCE_DIR}/qremote/conn.c
	${CMAKE_SOURCE_DIR}/qremote/starttlsr.c
	${CMAKE_SOURCE_DIR}/qremote/smtproutes.c
)
TARGET_LINK_LIBRARIES(Qsurvey
	qsmtp_lib
	owfat
)

ADD_EXECUTABLE(testspf testspf.c ${CMAKE_SOURCE_DIR}/qsmtpd/spf.c ${CMAKE_SOURCE_DIR}/qsmtpd/antispam.c)
TARGET_LINK_LIBRARIES(testspf
	qsmtp_lib
	owfat
)

ADD_EXECUTABLE(qpencode qp.c ${CMAKE_SOURCE_DIR}/qremote/qrdata.c)
TARGET_LINK_LIBRARIES(qpencode qsmtp_lib)
ADD_EXECUTABLE(clearpass clearpass.c)
TARGET_LINK_LIBRARIES(clearpass qsmtp_lib)
ADD_EXECUTABLE(addipbl addipbl.c)

INSTALL(TARGETS
		Qsurvey
		testspf
		qpencode
		clearpass
		addipbl
#		fcshell
	DESTINATION bin
	COMPONENT tools
)
