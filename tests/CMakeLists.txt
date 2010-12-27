SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -fprofile-arcs -ftest-coverage")

ADD_EXECUTABLE(testcase_spf
		spf_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/spf.c
		${CMAKE_SOURCE_DIR}/lib/dns_helpers.c
		${CMAKE_SOURCE_DIR}/lib/fmt.c
		${CMAKE_SOURCE_DIR}/lib/match.c
)

IF (MEMCHECK_LIBRARIES)
	TARGET_LINK_LIBRARIES(testcase_spf ${MEMCHECK_LIBRARIES})
ENDIF (MEMCHECK_LIBRARIES)

ADD_TEST(NAME "SPF_redhat" COMMAND testcase_spf "redhat")
ADD_TEST(NAME "SPF_sf-mail" COMMAND testcase_spf "sf-mail")

ADD_EXECUTABLE(testcase_control
		control_test.c
		${CMAKE_SOURCE_DIR}/lib/control.c
		${CMAKE_SOURCE_DIR}/lib/mmap.c)

IF (MEMCHECK_LIBRARIES)
	TARGET_LINK_LIBRARIES(testcase_control ${MEMCHECK_LIBRARIES})
ENDIF (MEMCHECK_LIBRARIES)

ADD_TEST(NAME "Control" COMMAND testcase_control)

ADD_EXECUTABLE(testcase_base64
		base64_test.c
		${CMAKE_SOURCE_DIR}/lib/base64.c)

IF (MEMCHECK_LIBRARIES)
	TARGET_LINK_LIBRARIES(testcase_base64 ${MEMCHECK_LIBRARIES})
ENDIF (MEMCHECK_LIBRARIES)

ADD_TEST(NAME "Base64" COMMAND testcase_base64)

ADD_EXECUTABLE(testcase_cdb
		cdb_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/vpop.c)
TARGET_LINK_LIBRARIES(testcase_cdb
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "CDB"
		COMMAND testcase_cdb "${CMAKE_CURRENT_SOURCE_DIR}")

ADD_EXECUTABLE(testcase_authsetup
		authsetup_test.c
		${CMAKE_SOURCE_DIR}/lib/base64.c
		${CMAKE_SOURCE_DIR}/lib/control.c
		${CMAKE_SOURCE_DIR}/lib/mmap.c
		${CMAKE_SOURCE_DIR}/qsmtpd/auth.c)

IF (MEMCHECK_LIBRARIES)
	TARGET_LINK_LIBRARIES(testcase_authsetup ${MEMCHECK_LIBRARIES})
ENDIF (MEMCHECK_LIBRARIES)

ADD_TEST(NAME "AUTH_Setup"
		COMMAND testcase_authsetup "${CMAKE_CURRENT_SOURCE_DIR}/authsetup")

ADD_EXECUTABLE(testcase_auth
		auth_test.c
		${CMAKE_SOURCE_DIR}/lib/base64.c
		${CMAKE_SOURCE_DIR}/lib/control.c
		${CMAKE_SOURCE_DIR}/lib/mmap.c
		${CMAKE_SOURCE_DIR}/qsmtpd/auth.c)

IF (MEMCHECK_LIBRARIES)
	TARGET_LINK_LIBRARIES(testcase_auth ${MEMCHECK_LIBRARIES})
ENDIF (MEMCHECK_LIBRARIES)

ADD_EXECUTABLE(auth_dummy auth_dummy.c)

ADD_TEST(NAME "AUTH"
		COMMAND testcase_auth "${CMAKE_CURRENT_BINARY_DIR}/auth_dummy")


ADD_EXECUTABLE(testcase_matchnet
		matchnet_test.c)

TARGET_LINK_LIBRARIES(testcase_matchnet
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "MatchNet"
		COMMAND testcase_matchnet)

ADD_EXECUTABLE(testcase_hostname
		hostname_test.c)

TARGET_LINK_LIBRARIES(testcase_hostname
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "Hostname"
		COMMAND testcase_hostname)

ADD_EXECUTABLE(testcase_xtext
		xtext_test.c)

TARGET_LINK_LIBRARIES(testcase_xtext
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "Xtext"
		COMMAND testcase_xtext)

ADD_EXECUTABLE(testcase_qrdata
		qrdata_test.c
		${CMAKE_SOURCE_DIR}/qremote/qrdata.c
		${CMAKE_SOURCE_DIR}/lib/mime.c
)

FOREACH(PATTERN
		simple
		crlfmixup
		dots
		"8bit+base64"
		longBodyLine
		longHeaderLine
		8bitLF)
	ADD_TEST(NAME "QrData-${PATTERN}"
			COMMAND testcase_qrdata ${PATTERN})
ENDFOREACH(PATTERN)

#
# SET_TARGET_PROPERTIES(testcase_spf
# 		testcase_control
# 		testcase_base64
# 		PROPERTIES
# 		LINK_FLAGS_DEBUG "-fprofile-arcs -ftest-coverage"
# )
