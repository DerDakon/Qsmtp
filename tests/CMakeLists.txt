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

FOREACH (AUTHTEST short email long)
	FOREACH (AUTHFLAG correct wrong)
		ADD_TEST(NAME "AUTH-LOGIN-${AUTHTEST}-${AUTHFLAG}"
				COMMAND testcase_auth "${CMAKE_CURRENT_BINARY_DIR}/auth_dummy" ${AUTHTEST} ${AUTHFLAG})
	ENDFOREACH (AUTHFLAG)
ENDFOREACH (AUTHTEST)

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
		longHeaderLineCR
		longHeaderLineLF
		longHeaderLine
		8bitLF
		noLFatEnd
		8bitHeader)
	ADD_TEST(NAME "QrData-${PATTERN}"
			COMMAND testcase_qrdata ${PATTERN})
ENDFOREACH(PATTERN)

SET_TESTS_PROPERTIES(QrData-8bitHeader PROPERTIES
		PASS_REGULAR_EXPRESSION "^D5\\.6\\.3 message contains unencoded 8bit data in message header")

ADD_EXECUTABLE(testcase_fmt
		fmt_test.c)
TARGET_LINK_LIBRARIES(testcase_fmt
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "Fmt"
		COMMAND testcase_fmt)

ADD_EXECUTABLE(testcase_addrsyntax
		addrsyntax_test.c)
TARGET_LINK_LIBRARIES(testcase_addrsyntax
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "AddrSyntax"
		COMMAND testcase_addrsyntax)

ADD_EXECUTABLE(testcase_mmap
		mmap_test.c)
TARGET_LINK_LIBRARIES(testcase_mmap
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "Mmap"
		COMMAND testcase_mmap)
