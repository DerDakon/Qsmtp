ADD_SUBDIRECTORY(test_io)

ADD_EXECUTABLE(testcase_spf
		spf_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/spf.c
		${CMAKE_SOURCE_DIR}/qsmtpd/antispam.c
)

TARGET_LINK_LIBRARIES(testcase_spf
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

ADD_TEST(NAME "SPF_received" COMMAND testcase_spf "_received_")
ADD_TEST(NAME "SPF_parser" COMMAND testcase_spf "_parse_")
ADD_TEST(NAME "SPF_testsuite" COMMAND testcase_spf "_suite_")
ADD_TEST(NAME "SPF_domain_redhat" COMMAND testcase_spf "redhat")
ADD_TEST(NAME "SPF_domain_sf-mail" COMMAND testcase_spf "sf-mail")

ADD_EXECUTABLE(testcase_control
		control_test.c)

TARGET_LINK_LIBRARIES(testcase_control
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

ADD_TEST(NAME "Control" COMMAND testcase_control)

ADD_EXECUTABLE(testcase_base64
		base64_test.c)

TARGET_LINK_LIBRARIES(testcase_base64
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

ADD_TEST(NAME "Base64" COMMAND testcase_base64)

ADD_EXECUTABLE(testcase_cdb
		cdb_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/vpop.c)
TARGET_LINK_LIBRARIES(testcase_cdb
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "CDB"
		COMMAND testcase_cdb "${CMAKE_CURRENT_SOURCE_DIR}")

ADD_EXECUTABLE(testcase_authsetup
		authsetup_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/auth.c)

TARGET_LINK_LIBRARIES(testcase_authsetup
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

ADD_TEST(NAME "AUTH_Setup"
		COMMAND testcase_authsetup "${CMAKE_CURRENT_SOURCE_DIR}/authsetup")

ADD_EXECUTABLE(testcase_auth
		auth_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/auth.c)

TARGET_LINK_LIBRARIES(testcase_auth
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

ADD_EXECUTABLE(auth_dummy auth_dummy.c)

FOREACH (AUTHTEST short email long)
	FOREACH (AUTHFLAG correct wrong)
		ADD_TEST(NAME "AUTH-LOGIN-${AUTHTEST}-${AUTHFLAG}"
				COMMAND testcase_auth "${CMAKE_CURRENT_BINARY_DIR}/auth_dummy" ${AUTHTEST} ${AUTHFLAG})
	ENDFOREACH (AUTHFLAG)
ENDFOREACH (AUTHTEST)

ADD_TEST(NAME "AUTH-LOGIN-errors"
		COMMAND testcase_auth "${CMAKE_CURRENT_BINARY_DIR}/auth_dummy" errors wrong)

ADD_EXECUTABLE(testcase_matchnet
		matchnet_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/antispam.c)

TARGET_LINK_LIBRARIES(testcase_matchnet
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "MatchNet"
		COMMAND testcase_matchnet)

ADD_EXECUTABLE(testcase_hostname
		hostname_test.c)

TARGET_LINK_LIBRARIES(testcase_hostname
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "Hostname"
		COMMAND testcase_hostname)

ADD_EXECUTABLE(testcase_xtext
		xtext_test.c)

TARGET_LINK_LIBRARIES(testcase_xtext
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "Xtext"
		COMMAND testcase_xtext)

ADD_EXECUTABLE(testcase_qrdata
		qrdata_test.c
		${CMAKE_SOURCE_DIR}/qremote/qrdata.c
)

TARGET_LINK_LIBRARIES(testcase_qrdata
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

FILE(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/qrdata_test_data")

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
		8bitHeader
		emptyLFheader
		emptyCRheader
		emptyLFheaderWith8bit
		emptyCRheaderWith8bit
		emptyCRLFheaderWith8bit
		NoEndBoundary
		EndInNotFinalBoundary
		EndsWithFinalBoundary
		MultipartNoBoundary
		longChunkBeforeRecode
		longChunkBeforeRecodeMultipart
		wrapHeadersWithLongParts
		InvalidPreamble)
	ADD_TEST(NAME "QrData-${PATTERN}"
			COMMAND testcase_qrdata ${PATTERN})
	SET_TESTS_PROPERTIES(QrData-${PATTERN} PROPERTIES
			ENVIRONMENT "QRDATA_INPUT_DIR=${CMAKE_CURRENT_SOURCE_DIR}")
	IF (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/qrdata_test_data/${PATTERN}.out")
		CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/qrdata_test_data/${PATTERN}.out"
			"${CMAKE_CURRENT_BINARY_DIR}/qrdata_test_data/${PATTERN}.out" @ONLY)
	ENDIF (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/qrdata_test_data/${PATTERN}.out")
ENDFOREACH(PATTERN)

SET_TESTS_PROPERTIES(QrData-8bitHeader PROPERTIES
		PASS_REGULAR_EXPRESSION "^D5\\.6\\.3 message contains unencoded 8bit data in message header")

ADD_EXECUTABLE(testcase_fmt
		fmt_test.c)
TARGET_LINK_LIBRARIES(testcase_fmt
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "Fmt"
		COMMAND testcase_fmt)

ADD_EXECUTABLE(testcase_addrsyntax
		addrsyntax_test.c)
TARGET_LINK_LIBRARIES(testcase_addrsyntax
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "AddrSyntax"
		COMMAND testcase_addrsyntax)

ADD_EXECUTABLE(testcase_mmap
		mmap_test.c)
TARGET_LINK_LIBRARIES(testcase_mmap
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "Mmap"
		COMMAND testcase_mmap)

ADD_EXECUTABLE(testcase_dns
		dns_test.c)
TARGET_LINK_LIBRARIES(testcase_dns
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "DNS"
		COMMAND testcase_dns)

ADD_EXECUTABLE(testcase_mime
		mime_test.c)
TARGET_LINK_LIBRARIES(testcase_mime
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "MIME"
		COMMAND testcase_mime)

ADD_EXECUTABLE(testcase_antispam
		antispam_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/antispam.c
)
TARGET_LINK_LIBRARIES(testcase_antispam
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "Antispam"
		COMMAND testcase_antispam)
