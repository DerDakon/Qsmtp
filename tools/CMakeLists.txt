# add_executable(fcshell fcshell.c)

add_executable(Qsurvey
	qsurvey.c
	${CMAKE_SOURCE_DIR}/qremote/client.c
	${CMAKE_SOURCE_DIR}/qremote/common_setup.c
	${CMAKE_SOURCE_DIR}/qremote/conn.c
	${CMAKE_SOURCE_DIR}/qremote/greeting.c
	${CMAKE_SOURCE_DIR}/qremote/starttlsr.c
	${CMAKE_SOURCE_DIR}/qremote/status.c
)
target_link_libraries(Qsurvey
	qsmtp_lib
	qsmtp_io_lib
	${MEMCHECK_LIBRARIES}
)

install(TARGETS
		Qsurvey
	DESTINATION ${CMAKE_INSTALL_BINDIR}
	COMPONENT tools
)

add_executable(testspf testspf.c ${CMAKE_SOURCE_DIR}/qsmtpd/spf.c ${CMAKE_SOURCE_DIR}/qsmtpd/antispam.c)
target_link_libraries(testspf
	qsmtp_lib
	qsmtp_io_lib
)

add_executable(spfquery spfquery.c ${CMAKE_SOURCE_DIR}/qsmtpd/spf.c ${CMAKE_SOURCE_DIR}/qsmtpd/antispam.c)
target_link_libraries(spfquery
	qsmtp_lib
	qsmtp_io_lib
)

add_executable(qpencode
	qp.c
	${CMAKE_SOURCE_DIR}/qremote/mime.c
	${CMAKE_SOURCE_DIR}/qremote/qrdata.c
)
target_link_libraries(qpencode
	qsmtp_lib
	qsmtp_io_lib
)

add_executable(clearpass clearpass.c)
target_link_libraries(clearpass
	qsmtp_lib
	qsmtp_io_lib
)

add_executable(addipbl addipbl.c)

add_executable(sendremote sendremote.c)

include_directories(
		${OWFAT_INCLUDE_DIRS}
)

install(TARGETS
		testspf
		qpencode
		clearpass
		addipbl
		sendremote
#		fcshell
	DESTINATION ${CMAKE_INSTALL_BINDIR}
	COMPONENT tools
)

add_executable(dnsdane dnsdane.c)
target_link_libraries(dnsdane
	qsmtp_dane_lib
	qsmtp_lib
)

add_executable(dnstxt dnstxt.c)
target_link_libraries(dnstxt
	qsmtp_io_lib
	qsmtp_lib
)

if (BUILD_TESTING)
	add_subdirectory(tests)
endif ()
