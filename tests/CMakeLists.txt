# check if the qmail directory is maintained by the build, which means
# we are running inside the testsuite and can mess with that directory
IF (AUTOQMAIL MATCHES "^${CMAKE_BINARY_DIR}/")
	SET(AUTOQMAIL_FROM_TESTSUITE TRUE)
	file(WRITE "${CMAKE_BINARY_DIR}/var/qmail/control/outgoingip" "192.0.2.61")
	file(WRITE "${CMAKE_BINARY_DIR}/var/qmail/control/outgoingip6" "fd38:d30d:f257:35ac::42")
ELSE ()
	SET(AUTOQMAIL_FROM_TESTSUITE FALSE)
ENDIF ()

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
ADD_TEST(NAME "SPF_behavior" COMMAND testcase_spf "_behavior_")
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
		cdb_entries.h)
TARGET_LINK_LIBRARIES(testcase_cdb
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "CDB"
		COMMAND testcase_cdb
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

ADD_EXECUTABLE(testcase_authsetup
		authsetup_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/auth.c)

TARGET_LINK_LIBRARIES(testcase_authsetup
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

ADD_TEST(NAME "AUTH_Setup"
		COMMAND testcase_authsetup "${CMAKE_CURRENT_SOURCE_DIR}/authsetup")

ADD_EXECUTABLE(testcase_auth_errors
		auth_errors_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/auth.c)

TARGET_LINK_LIBRARIES(testcase_auth_errors
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

ADD_TEST(NAME "AUTH_errors"
		COMMAND testcase_auth_errors)

ADD_EXECUTABLE(testcase_auth_be_cp
		auth_be_cp_test.c)

TARGET_LINK_LIBRARIES(testcase_auth_be_cp
		Qsmtpd_auth_checkpassword
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

ADD_TEST(NAME "AUTH_BE_chkpw"
		COMMAND testcase_auth_be_cp "${CMAKE_CURRENT_BINARY_DIR}/auth_dummy")

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
		FOREACH (AUTHMECH LOGIN PLAIN)
			ADD_TEST(NAME "AUTH-${AUTHMECH}-${AUTHTEST}-${AUTHFLAG}"
					COMMAND testcase_auth "${CMAKE_CURRENT_BINARY_DIR}/auth_dummy" ${AUTHTEST} ${AUTHMECH} ${AUTHFLAG})
		ENDFOREACH (AUTHMECH)
	ENDFOREACH (AUTHFLAG)
ENDFOREACH (AUTHTEST)

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
		xtext_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrsyntax.c
		${CMAKE_SOURCE_DIR}/qsmtpd/xtext.c)

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
		NoEndBoundaryShortEnd
		EndInNotFinalBoundary
		EndsWithFinalBoundary
		MultipartNoBoundary
		longChunkBeforeRecode
		longChunkBeforeRecodeMultipart
		wrapHeadersWithLongParts
		whitespaceBeforeLinebreak
		8bitAroundSoftbreak
		ContentTypeSyntaxError
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
		PASS_REGULAR_EXPRESSION "^(.*\n)?D5\\.6\\.3 message contains unencoded 8bit data in message header")

SET_TESTS_PROPERTIES(QrData-ContentTypeSyntaxError PROPERTIES
		PASS_REGULAR_EXPRESSION "^(.*\n)?D5\\.6\\.3 syntax error in Content-Type message header")

ADD_TEST(NAME QrData-DATA-4xx-error COMMAND testcase_qrdata data_reply_400 temporary error)
SET_TESTS_PROPERTIES(QrData-DATA-4xx-error PROPERTIES
		PASS_REGULAR_EXPRESSION "^(.*\n)?Z4\\.3\\.0 .*temporary error")

ADD_TEST(NAME QrData-DATA-5xx-error COMMAND testcase_qrdata data_reply_500 permanent error)
SET_TESTS_PROPERTIES(QrData-DATA-5xx-error PROPERTIES
		PASS_REGULAR_EXPRESSION "^(.*\n)?D5\\.3\\.0 .*permanent error")

ADD_EXECUTABLE(testcase_qrbdat
		qrbdat_test.c
		${CMAKE_SOURCE_DIR}/qremote/qrbdat.c
)

TARGET_LINK_LIBRARIES(testcase_qrbdat
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "QrBDAT"
		COMMAND testcase_qrbdat)

ADD_EXECUTABLE(testcase_fmt
		fmt_test.c)
TARGET_LINK_LIBRARIES(testcase_fmt
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "Fmt"
		COMMAND testcase_fmt)

ADD_EXECUTABLE(testcase_addrparse
		addrparse_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrparse.c)
TARGET_LINK_LIBRARIES(testcase_addrparse
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "AddrParse"
		COMMAND testcase_addrparse)

ADD_EXECUTABLE(testcase_addrsyntax
		addrsyntax_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrsyntax.c)
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

ADD_EXECUTABLE(testcase_qdns
		qdns_test.c
		../lib/qdns.c)
TARGET_LINK_LIBRARIES(testcase_qdns
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "QDNS"
		COMMAND testcase_qdns)

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

ADD_EXECUTABLE(testcase_all_filters
		all_filters_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/antispam.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrsyntax.c
		${CMAKE_SOURCE_DIR}/qsmtpd/getfile.c
)
TARGET_LINK_LIBRARIES(testcase_all_filters
		rcptfilters
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)
ADD_TEST(NAME "All_Filters"
		COMMAND testcase_all_filters
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/all_filters")

ADD_EXECUTABLE(testcase_filter_badcc
		filter_badcc_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/filters/badcc.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrsyntax.c
		${CMAKE_SOURCE_DIR}/qsmtpd/getfile.c
)
TARGET_LINK_LIBRARIES(testcase_filter_badcc
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)
ADD_TEST(NAME "Filter-badCC"
		COMMAND testcase_filter_badcc ${CMAKE_CURRENT_SOURCE_DIR}/filter_badcc)

ADD_EXECUTABLE(testcase_filter_nomail
		filter_nomail_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/getfile.c
		${CMAKE_SOURCE_DIR}/qsmtpd/filters/nomail.c
)
TARGET_LINK_LIBRARIES(testcase_filter_nomail
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)
ADD_TEST(NAME "Filter-NoMail"
		COMMAND testcase_filter_nomail)

ADD_EXECUTABLE(testcase_filter_fromdomain
		filter_fromdomain_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/filters/fromdomain.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrsyntax.c
		${CMAKE_SOURCE_DIR}/qsmtpd/getfile.c
)
TARGET_LINK_LIBRARIES(testcase_filter_fromdomain
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)
ADD_TEST(NAME "Filter-FromDomain"
		COMMAND testcase_filter_fromdomain)

ADD_EXECUTABLE(testcase_getfile
		getfile_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/getfile.c)
TARGET_LINK_LIBRARIES(testcase_getfile
		${MEMCHECK_LIBRARIES}
)
ADD_TEST(NAME "Getfile"
		COMMAND testcase_getfile)

ADD_EXECUTABLE(testcase_getsetting
		getsetting_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/getfile.c)
TARGET_LINK_LIBRARIES(testcase_getsetting
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
)
ADD_TEST(NAME "Getsetting"
		COMMAND testcase_getsetting)

ADD_EXECUTABLE(testcase_netio
		netio_test.c)
TARGET_LINK_LIBRARIES(testcase_netio
		qsmtp_io_lib)
ADD_TEST(NAME "NetIO"
		COMMAND testcase_netio)

ADD_EXECUTABLE(testcase_smtproutes
		smtproutes_test.c
		${CMAKE_SOURCE_DIR}/qremote/smtproutes.c)
TARGET_LINK_LIBRARIES(testcase_smtproutes
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

FOREACH (ROUTETEST nomatch complete_match with_port port_0 port_100k port_char port_char_no_relay
		no_colon port_only unresolved
		complete_match_dir with_port_dir port_0_dir port_100k_dir port_char_dir port_only_dir
		port_char_no_relay_dir unresolved_dir duplicate_host_dir invalid_entry_dir
		no_equal_dir start_equal_dir)
	ADD_TEST(NAME "SMTProutes-${ROUTETEST}"
			COMMAND testcase_smtproutes
			WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/smtproutes/${ROUTETEST}")
	IF (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/smtproutes/${ROUTETEST}/errmsg")
		FILE(READ "${CMAKE_CURRENT_SOURCE_DIR}/smtproutes/${ROUTETEST}/errmsg" ROUTETEST_MSG)
		SET_TESTS_PROPERTIES(SMTProutes-${ROUTETEST} PROPERTIES
			PASS_REGULAR_EXPRESSION "^(.*\n)?LOG: ${ROUTETEST_MSG}(\n.*)?$")
	ENDIF ()
ENDFOREACH (ROUTETEST)

ADD_EXECUTABLE(testcase_getmxlist
		getmxlist_test.c
		${CMAKE_SOURCE_DIR}/qremote/conn.c)

TARGET_LINK_LIBRARIES(testcase_getmxlist
		testcase_io_lib
		qsmtp_lib
		${MEMCHECK_LIBRARIES})

ADD_TEST(NAME "getmxlist"
		COMMAND testcase_getmxlist)

ADD_EXECUTABLE(testcase_getmxlistv4only
		getmxlist_test.c
		${CMAKE_SOURCE_DIR}/qremote/conn.c)

TARGET_LINK_LIBRARIES(testcase_getmxlistv4only
		testcase_io_lib
		qsmtp_lib
		${MEMCHECK_LIBRARIES})

SET_TARGET_PROPERTIES(testcase_getmxlistv4only PROPERTIES
		COMPILE_DEFINITIONS IPV4ONLY)

ADD_TEST(NAME "getmxlist_IPv4_only"
		COMMAND testcase_getmxlistv4only)

# This is a brute force test just to get some "real" coverage on the file.
# It will always fail, either because ${AUTOQMAIL} doesn't exist or doesn't
# have the proper configuration files or simply because we do not pass it
# any arguments.
ADD_TEST(NAME "Qremote_noinput_noargs"
		COMMAND Qremote)

# In case we have a proper configuration this may even check some more lines.
# Since the destination address should really not exists this will still fail.
ADD_TEST(NAME "Qremote_to_invalid"
		COMMAND Qremote invalid.invalid from@invalid.invalid to@invalid.invalid)
ADD_TEST(NAME "Qremote_to_localhost"
		COMMAND Qremote "[127.0.0.1]" "from@invalid.invalid" "to@[127.0.0.1]")
ADD_TEST(NAME "Qremote_to_localhost6"
		COMMAND Qremote "[::1]" "from@invalid.invalid" "to@[::1]")
ADD_TEST(NAME "Qremote_to_bad_expression"
		COMMAND Qremote "[127.0" "from@invalid.invalid" "to@localhost")
ADD_TEST(NAME "Qremote_to_bad_expression2"
		COMMAND Qremote "[127.0.a.v]" "from@invalid.invalid" "to@localhost")
ADD_TEST(NAME "Qremote_to_ip"
		COMMAND Qremote "[192.0.2.19]" "from@invalid.invalid" "to@localhost")

IF (AUTOQMAIL_FROM_TESTSUITE)
	SET_TESTS_PROPERTIES(Qremote_noinput_noargs PROPERTIES
			PASS_REGULAR_EXPRESSION "^Zinternal error: Qremote called with invalid arguments\n")
	SET_TESTS_PROPERTIES(Qremote_to_invalid PROPERTIES
			PASS_REGULAR_EXPRESSION "^Z4\\.4\\.3 cannot find a mail exchanger for invalid\\.invalid\n")
	SET_TESTS_PROPERTIES(Qremote_to_localhost PROPERTIES
			PASS_REGULAR_EXPRESSION "^Z4\\.4\\.3 all mail exchangers for \\[127\\.0\\.0\\.1\\] point back to me\n")
	SET_TESTS_PROPERTIES(Qremote_to_localhost6 PROPERTIES
			PASS_REGULAR_EXPRESSION "^Z4\\.4\\.3 all mail exchangers for \\[::1\\] point back to me\n")
	SET_TESTS_PROPERTIES(Qremote_to_bad_expression Qremote_to_bad_expression2 PROPERTIES
			PASS_REGULAR_EXPRESSION "^Z4\\.3\\.0 parse error in first argument\n")
	SET_TESTS_PROPERTIES(Qremote_to_ip PROPERTIES
			PASS_REGULAR_EXPRESSION "^Zinternal error: can't mmap\\(\\) input\n")
ELSE ()
	SET_TESTS_PROPERTIES(Qremote_noinput_noargs Qremote_to_invalid
			Qremote_to_localhost Qremote_to_localhost6
			Qremote_to_bad_expression Qremote_to_bad_expression2
			Qremote_to_ip
			PROPERTIES
			PASS_REGULAR_EXPRESSION "^Z")
ENDIF ()

ADD_EXECUTABLE(testcase_qsdata
		qsdata_test.c
)

TARGET_LINK_LIBRARIES(testcase_qsdata
		testcase_io_lib
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "Qsmtpd_data"
		COMMAND testcase_qsdata)

# Another brute force test, this time for Qsmtpd
SET(TEST_SEQUENCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/quit.cmake")
CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_quit.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_quit.cmake" @ONLY)
ADD_TEST(NAME "Qsmtpd_quit"
		COMMAND "${CMAKE_COMMAND}"
				-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_quit.cmake")

CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_quit_no_ips.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_quit_no_ips.cmake" @ONLY)
ADD_TEST(NAME "Qsmtpd_quit_no_ips"
		COMMAND "${CMAKE_COMMAND}"
				-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_quit_no_ips.cmake")

# Do not add \r here, looks like CMake automatically strips it, so just
# assume we are doing it right.
SET_TESTS_PROPERTIES(Qsmtpd_quit Qsmtpd_quit_no_ips PROPERTIES
		PASS_REGULAR_EXPRESSION "^220 [^\n ]* Qsmtpd ${QSMTP_VERSION} ESMTP\n221 2\\.0\\.0 [^\n ]* service closing transmission channel\n$")

SET(TEST_SEQUENCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/postmaster_rset.cmake")
CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_quit.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_quit_postmaster.cmake" @ONLY)
ADD_TEST(NAME "Qsmtpd_postmaster_rset"
		COMMAND "${CMAKE_COMMAND}"
				-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_quit_postmaster.cmake")

# Do not add \r here, looks like CMake automatically strips it, so just
# assume we are doing it right.
SET_TESTS_PROPERTIES(Qsmtpd_postmaster_rset PROPERTIES
		PASS_REGULAR_EXPRESSION "^220 [^\n ]* Qsmtpd ${QSMTP_VERSION} ESMTP\n250 [^\n ]*\n250 2\\.0\\.0 ok\n250 2\\.0\\.0 ok\n250-[^\n ]*\n250-ENHANCEDSTATUSCODES\n250-PIPELINING\n250-8BITMIME\n(.*\n)?250 SIZE( [0-9]+)?\n250 2\\.1\\.5 sender <> is syntactically correct\n250 2\\.1\\.0 recipient <postmaster> OK\n250 2\\.0\\.0 ok\n503 5\\.5\\.1 Bad sequence of commands\n221 2\\.0\\.0 [^\n ]* service closing transmission channel\n$")

SET(TEST_SEQUENCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/bounce_multi_rcpt.cmake")
CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_quit.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_bad_bounce.cmake" @ONLY)
ADD_TEST(NAME "Qsmtpd_bad_bounce"
		COMMAND "${CMAKE_COMMAND}"
				-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_bad_bounce.cmake")

# Do not add \r here, looks like CMake automatically strips it, so just
# assume we are doing it right.
SET_TESTS_PROPERTIES(Qsmtpd_bad_bounce PROPERTIES
		PASS_REGULAR_EXPRESSION "^220 [^\n ]* Qsmtpd ${QSMTP_VERSION} ESMTP\n250-[^\n ]*\n250-ENHANCEDSTATUSCODES\n250-PIPELINING\n250-8BITMIME\n(.*\n)?250 SIZE( [0-9]+)?\n250 2\\.1\\.5 sender <> is syntactically correct\n250 2\\.1\\.0 recipient <postmaster> OK\n550 5\\.5\\.3 bounce messages must not have more than one recipient\n554 5\\.1\\.1 no valid recipients\n221 2\\.0\\.0 [^\n ]* service closing transmission channel\n$")

SET(TEST_SEQUENCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cmd_args.cmake")
CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_quit.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_cmd_args.cmake" @ONLY)
ADD_TEST(NAME "Qsmtpd_cmd_args"
		COMMAND "${CMAKE_COMMAND}"
				-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_cmd_args.cmake")
# Do not add \r here, looks like CMake automatically strips it, so just
# assume we are doing it right.
SET_TESTS_PROPERTIES(Qsmtpd_cmd_args PROPERTIES
		PASS_REGULAR_EXPRESSION "^220 [^\n ]* Qsmtpd ${QSMTP_VERSION} ESMTP\n250 [^\n ]*\n250 [^\n ]*\n500 5\\.5\\.2 command syntax error\n250-[^\n ]*\n250-ENHANCEDSTATUSCODES\n250-PIPELINING\n250-8BITMIME\n(.*\n)?250 SIZE( [0-9]+)?\n501 5\\.5\\.2 unrecognized command parameter\n250 2\\.1\\.5 sender <> is syntactically correct\n250 2\\.0\\.0 ok\n500 5\\.5\\.2 command syntax error\n250 2\\.1\\.5 sender <> is syntactically correct\n500 5\\.5\\.2 command syntax error\n501 5\\.1\\.3 domain of mail address is syntactically incorrect\n250 2\\.0\\.0 ok\n250 2\\.1\\.5 sender <> is syntactically correct\n(500 5\\.5\\.2 command syntax error\n250 2\\.0\\.0 ok\n)+500-5\\.5\\.2 line too long\n500-5\\.5\\.2 This is usually a bug in your mail client\n500 5\\.5\\.2 Try to use a different encoding like quoted-printable for this mail.\n250 2.0.0 ok\n501 5\\.1\\.3 domain of mail address is syntactically incorrect\n250 2\\.0\\.0 ok\n500 5\\.5\\.2 command syntax error\n503 5\\.5\\.1 SMTP command sent after end of PIPELINING command group\n503 5\\.5\\.1 Bad sequence of commands\n221 2\\.0\\.0 [^\n ]* service closing transmission channel\n$")

SET(TEST_SEQUENCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/bad_pipelining.cmake")
CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_quit.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_bad_pipelining.cmake" @ONLY)
ADD_TEST(NAME "Qsmtpd_bad_pipelining"
		COMMAND "${CMAKE_COMMAND}"
				-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_bad_pipelining.cmake")
# Do not add \r here, looks like CMake automatically strips it, so just
# assume we are doing it right.
SET_TESTS_PROPERTIES(Qsmtpd_bad_pipelining PROPERTIES
		PASS_REGULAR_EXPRESSION "^220 [^\n ]* Qsmtpd ${QSMTP_VERSION} ESMTP\n250 [^\n ]*\n550 5\\.5\\.0 you must wait for my reply\n503 5\\.5\\.1 Bad sequence of commands\n503 5\\.5\\.1 Bad sequence of commands\n221 2\\.0\\.0 [^\n ]* service closing transmission channel\n$")

SET(TEST_SEQUENCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/no_auth_submission.cmake")
CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_submission.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_no_auth_submission.cmake" @ONLY)
ADD_TEST(NAME "Qsmtpd_no_auth_submission"
		COMMAND "${CMAKE_COMMAND}"
				-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_no_auth_submission.cmake")
# Do not add \r here, looks like CMake automatically strips it, so just
# assume we are doing it right.
SET_TESTS_PROPERTIES(Qsmtpd_no_auth_submission PROPERTIES
		PASS_REGULAR_EXPRESSION "^220 [^\n ]* Qsmtpd ${QSMTP_VERSION} ESMTP\n(250-[^\n]+\n)+250-AUTH [^\n]+\n(250-[^\n]+\n)*250 [^\n]+\n550 5.7.1 authentication required\n221 2\\.0\\.0 [^\n ]* service closing transmission channel\n$")

ADD_EXECUTABLE(testcase_ipme
		ipme_test.c)
TARGET_LINK_LIBRARIES(testcase_ipme
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)
ADD_TEST(NAME "IPme"
		COMMAND testcase_ipme)

ADD_EXECUTABLE(testcase_ehlo_parsing
		ehlo_test.c
		${CMAKE_SOURCE_DIR}/qremote/greeting.c
)
TARGET_LINK_LIBRARIES(testcase_ehlo_parsing
		${MEMCHECK_LIBRARIES}
)
ADD_TEST(NAME "EHLO_parsing"
		COMMAND testcase_ehlo_parsing)


ADD_EXECUTABLE(testcase_vpop_user_exists
		userexists_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/getfile.c
		${CMAKE_SOURCE_DIR}/qsmtpd/vpop.c)
TARGET_LINK_LIBRARIES(testcase_vpop_user_exists
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)
ADD_TEST(NAME "VPop_user_exists"
		COMMAND testcase_vpop_user_exists
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/user_exists/")

ADD_EXECUTABLE(testcase_vpop_vget_dir
		vpop_vget_dir_test.c
		cdb_entries.h
		${CMAKE_SOURCE_DIR}/qsmtpd/getfile.c
		${CMAKE_SOURCE_DIR}/qsmtpd/vpop.c)
TARGET_LINK_LIBRARIES(testcase_vpop_vget_dir
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

ADD_TEST(NAME "VPop_vget_dir"
		COMMAND testcase_vpop_vget_dir "${CMAKE_CURRENT_SOURCE_DIR}")
