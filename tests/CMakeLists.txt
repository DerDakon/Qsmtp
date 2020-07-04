# check if the qmail directory is maintained by the build, which means
# we are running inside the testsuite and can mess with that directory
if (AUTOQMAIL MATCHES "^${CMAKE_BINARY_DIR}/")
	set(AUTOQMAIL_FROM_TESTSUITE TRUE)
	file(WRITE "${AUTOQMAIL}/control/outgoingip" "192.0.2.61")
	file(WRITE "${AUTOQMAIL}/control/outgoingip6" "fd38:d30d:f257:35ac::42")
	file(WRITE "${AUTOQMAIL}/control/databytes" "1024")
	file(STRINGS "${AUTOQMAIL}/control/me" QSMTPD_GREETING_LINE LIMIT_COUNT 1 NO_HEX_CONVERSION)
	set(QSMTPD_QUIT_LINE "221 2\\.0\\.0 ${QSMTPD_GREETING_LINE} service closing transmission channel\n")
	set(QSMTPD_HELO_RESPONSE "250 ${QSMTPD_GREETING_LINE}\n")
	set(QSMTPD_GREETING_LINE "220 ${QSMTPD_GREETING_LINE} Qsmtpd ${QSMTP_VERSION} ESMTP\n")
else ()
	set(AUTOQMAIL_FROM_TESTSUITE FALSE)
	set(QSMTPD_QUIT_LINE "221 2\\.0\\.0 [^\n ]* service closing transmission channel\n")
	set(QSMTPD_HELO_RESPONSE "250 [^\n ]*\n")
	set(QSMTPD_GREETING_LINE "220 [^\n ]* Qsmtpd ${QSMTP_VERSION} ESMTP\n")
endif ()

if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
	set(PROFILE_MSG "(LLVM Profile Note: Set profile file path to \".*\" via default setting\\.\n)?")
else ()
	set(PROFILE_MSG "")
endif ()

# libowfat changed that function signature between 0.29 and 0.30
include(CheckPrototypeDefinition)

set(CMAKE_REQUIRED_INCLUDES "${OWFAT_INCLUDE_DIR}")
check_prototype_definition(dns_domain_fromdot
  "int dns_domain_fromdot(char **q, const char *host, unsigned int len)"
  "-1"
  "dns.h"
  LIBOWFAT_UINT_DNSDOMFD)

if (NOT CMAKE_SYSTEM_NAME STREQUAL "FreeBSD"
		AND NOT CMAKE_SYSTEM_NAME STREQUAL "NetBSD"
		AND NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
	# FreeBSD has everything visible by default
	# MacOS does not have O_DIRECTORY in _POSIX_C_SOURCE 200809L
	add_definitions(-D_DEFAULT_SOURCE -D_BSD_SOURCE -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700)
endif ()

add_subdirectory(test_io)

add_executable(testcase_spf
		spf_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/spf.c
		${CMAKE_SOURCE_DIR}/qsmtpd/antispam.c
		${CMAKE_SOURCE_DIR}/qremote/mime.c # for skipwhitespace()
)

target_link_libraries(testcase_spf
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

add_test(NAME "SPF_received" COMMAND testcase_spf "_received_")
add_test(NAME "SPF_parser" COMMAND testcase_spf "_parse_")
add_test(NAME "SPF_behavior" COMMAND testcase_spf "_behavior_")
add_test(NAME "SPF_testsuite" COMMAND testcase_spf "_suite_")
add_test(NAME "SPF_domain_redhat" COMMAND testcase_spf "redhat")
add_test(NAME "SPF_domain_sf-mail" COMMAND testcase_spf "sf-mail")

add_executable(testcase_control
		control_test.c)

target_link_libraries(testcase_control
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

add_test(NAME "Control" COMMAND testcase_control)

add_executable(testcase_base64
		base64_test.c)

target_link_libraries(testcase_base64
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

add_test(NAME "Base64" COMMAND testcase_base64)

add_executable(testcase_cdb
		cdb_test.c
		cdb_entries.h)
target_link_libraries(testcase_cdb
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "CDB"
		COMMAND testcase_cdb
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(testcase_authsetup
		authsetup_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/auth.c)

target_link_libraries(testcase_authsetup
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

if (HAS_BSD_EXP_BZERO)
	target_link_libraries(testcase_authsetup
		${LIBBSD}
	)
endif()

add_test(NAME "AUTH_Setup"
		COMMAND testcase_authsetup "${CMAKE_CURRENT_SOURCE_DIR}/authsetup")

add_executable(testcase_auth_errors
		auth_errors_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/auth.c)

target_link_libraries(testcase_auth_errors
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

if (HAS_BSD_EXP_BZERO)
	target_link_libraries(testcase_auth_errors
		${LIBBSD}
	)
endif()

add_test(NAME "AUTH_errors"
		COMMAND testcase_auth_errors)

add_executable(testcase_auth_be_cp
		auth_be_cp_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/child.c
)

target_link_libraries(testcase_auth_be_cp
		Qsmtpd_auth_checkpassword
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

add_test(NAME "AUTH_BE_chkpw"
		COMMAND testcase_auth_be_cp "${CMAKE_CURRENT_BINARY_DIR}/auth_dummy")

add_executable(testcase_auth
		auth_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/auth.c
		${CMAKE_SOURCE_DIR}/qsmtpd/child.c
)

target_link_libraries(testcase_auth
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

if (HAS_BSD_EXP_BZERO)
	target_link_libraries(testcase_auth
		${LIBBSD}
	)
endif()

add_executable(auth_dummy auth_dummy.c)

foreach (AUTHTEST short email long)
	foreach (AUTHFLAG correct wrong)
		foreach (AUTHMECH LOGIN PLAIN)
			add_test(NAME "AUTH-${AUTHMECH}-${AUTHTEST}-${AUTHFLAG}"
					COMMAND testcase_auth "${CMAKE_CURRENT_BINARY_DIR}/auth_dummy" ${AUTHTEST} ${AUTHMECH} ${AUTHFLAG})
		endforeach ()
	endforeach ()
endforeach ()

add_executable(testcase_matchnet
		matchnet_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/antispam.c)

target_link_libraries(testcase_matchnet
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "MatchNet"
		COMMAND testcase_matchnet)

add_executable(testcase_hostname
		hostname_test.c)

target_link_libraries(testcase_hostname
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "Hostname"
		COMMAND testcase_hostname)

add_executable(testcase_xtext
		xtext_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrsyntax.c
		${CMAKE_SOURCE_DIR}/qsmtpd/xtext.c)

target_link_libraries(testcase_xtext
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "Xtext"
		COMMAND testcase_xtext)

add_executable(testcase_qrdata
		qrdata_test.c
		${CMAKE_SOURCE_DIR}/qremote/qrdata.c
		${CMAKE_SOURCE_DIR}/qremote/mime.c
		${CMAKE_SOURCE_DIR}/lib/utf8.c
)

target_link_libraries(testcase_qrdata
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/qrdata_test_data")

foreach(PATTERN
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
	add_test(NAME "QrData-${PATTERN}"
			COMMAND testcase_qrdata ${PATTERN})
	set_tests_properties(QrData-${PATTERN} PROPERTIES
			ENVIRONMENT "QRDATA_INPUT_DIR=${CMAKE_CURRENT_SOURCE_DIR}")
	if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/qrdata_test_data/${PATTERN}.out")
		configure_file("${CMAKE_CURRENT_SOURCE_DIR}/qrdata_test_data/${PATTERN}.out"
			"${CMAKE_CURRENT_BINARY_DIR}/qrdata_test_data/${PATTERN}.out" @ONLY)
	endif ()
endforeach()

set_tests_properties(QrData-8bitHeader PROPERTIES
		PASS_REGULAR_EXPRESSION "^(.*\n)?D5\\.6\\.3 message contains unencoded 8bit data in message header")

set_tests_properties(QrData-ContentTypeSyntaxError PROPERTIES
		PASS_REGULAR_EXPRESSION "^(.*\n)?D5\\.6\\.3 syntax error in Content-Type message header")

add_test(NAME QrData-DATA-4xx-error COMMAND testcase_qrdata data_reply_400 temporary error)
set_tests_properties(QrData-DATA-4xx-error PROPERTIES
		PASS_REGULAR_EXPRESSION "^(.*\n)?Z4\\.3\\.0 .*temporary error")

add_test(NAME QrData-DATA-5xx-error COMMAND testcase_qrdata data_reply_500 permanent error)
set_tests_properties(QrData-DATA-5xx-error PROPERTIES
		PASS_REGULAR_EXPRESSION "^(.*\n)?D5\\.3\\.0 .*permanent error")

add_executable(testcase_qrbdat
		qrbdat_test.c
		${CMAKE_SOURCE_DIR}/qremote/qrbdat.c
)

target_link_libraries(testcase_qrbdat
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "QrBDAT"
		COMMAND testcase_qrbdat)

add_executable(testcase_fmt
		fmt_test.c)
target_link_libraries(testcase_fmt
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "Fmt"
		COMMAND testcase_fmt)

add_executable(testcase_addrparse
		addrparse_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrparse.c)
target_link_libraries(testcase_addrparse
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "AddrParse"
		COMMAND testcase_addrparse)

add_executable(testcase_addrsyntax
		addrsyntax_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrsyntax.c)
target_link_libraries(testcase_addrsyntax
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "AddrSyntax"
		COMMAND testcase_addrsyntax)

add_executable(testcase_mmap
		mmap_test.c)
target_link_libraries(testcase_mmap
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "Mmap"
		COMMAND testcase_mmap)

add_executable(testcase_dns
		dns_test.c)
target_link_libraries(testcase_dns
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "DNS"
		COMMAND testcase_dns)

add_executable(testcase_qdns
		qdns_test.c
		../lib/qdns.c)
target_link_libraries(testcase_qdns
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "QDNS"
		COMMAND testcase_qdns)

add_executable(testcase_qdns_dane
		qdns_dane_test.c
		${CMAKE_SOURCE_DIR}/lib/qdns_dane.c
)
target_link_libraries(testcase_qdns_dane
		qsmtp_lib
		owfat::owfat
		${MEMCHECK_LIBRARIES}
)
if (COMMAND target_compile_definitions)
	target_compile_definitions(testcase_qdns_dane PRIVATE -DLIBOWFAT_UINT_DNSDOMFD=${LIBOWFAT_UINT_DNSDOMFD})
else ()
	add_definitions(-DLIBOWFAT_UINT_DNSDOMFD=${LIBOWFAT_UINT_DNSDOMFD})
endif ()

add_test(NAME "QDNS_DANE"
		COMMAND testcase_qdns_dane)

add_executable(testcase_mime
		mime_test.c
		${CMAKE_SOURCE_DIR}/qremote/mime.c
)
target_link_libraries(testcase_mime
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "MIME"
		COMMAND testcase_mime)

add_executable(testcase_mime_boundary
		mime_boundary_test.c
		${CMAKE_SOURCE_DIR}/qremote/mime.c
)
target_link_libraries(testcase_mime_boundary
# 		qsmtp_lib
# 		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "MIME_boundary_empty"
		COMMAND testcase_mime_boundary "\"\"")
set_tests_properties(MIME_boundary_empty PROPERTIES
		PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}D5.6.3 boundary definition is empty\n$")

add_test(NAME "MIME_boundary_long"
		COMMAND testcase_mime_boundary "a123456789b123456789c123456789d123456789e123456789f123456789g123456789h")
set_tests_properties(MIME_boundary_long PROPERTIES
		PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}D5.6.3 boundary definition is too long\n$")

add_test(NAME "MIME_boundary_invalid"
		COMMAND testcase_mime_boundary "#")
set_tests_properties(MIME_boundary_invalid PROPERTIES
		PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}D5.6.3 boundary definition contains invalid character\n$")

add_test(NAME "MIME_boundary_quoted_space"
		COMMAND testcase_mime_boundary "\"a \"")
set_tests_properties(MIME_boundary_quoted_space PROPERTIES
		PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}D5.6.3 quoted boundary definition may not end in space\n$")

add_executable(testcase_antispam
		antispam_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/antispam.c
)
target_link_libraries(testcase_antispam
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "Antispam"
		COMMAND testcase_antispam)

add_executable(testcase_all_filters
		all_filters_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/antispam.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrsyntax.c
		${CMAKE_SOURCE_DIR}/qsmtpd/backends/user_vpopm/getfile.c
)
target_link_libraries(testcase_all_filters
		rcptfilters
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)
add_test(NAME "All_Filters"
		COMMAND testcase_all_filters
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/all_filters")

add_executable(testcase_filter_badcc
		filter_badcc_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/filters/badcc.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrsyntax.c
)
target_link_libraries(testcase_filter_badcc
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)
add_test(NAME "Filter-badCC"
		COMMAND testcase_filter_badcc)

add_executable(testcase_filter_nomail
		filter_nomail_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/backends/user_vpopm/getfile.c
		${CMAKE_SOURCE_DIR}/qsmtpd/filters/nomail.c
)
target_link_libraries(testcase_filter_nomail
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)
add_test(NAME "Filter-NoMail"
		COMMAND testcase_filter_nomail)

add_executable(testcase_filter_fromdomain
		filter_fromdomain_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/filters/fromdomain.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrsyntax.c
		${CMAKE_SOURCE_DIR}/qsmtpd/backends/user_vpopm/getfile.c
)
target_link_libraries(testcase_filter_fromdomain
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)
add_test(NAME "Filter-FromDomain"
		COMMAND testcase_filter_fromdomain)


add_executable(testcase_filter_spf
		filter_spf.c
		${CMAKE_SOURCE_DIR}/qsmtpd/filters/spf.c
		${CMAKE_SOURCE_DIR}/qsmtpd/filters/rcpt_filters.c
)
target_link_libraries(testcase_filter_spf
		qsmtp_lib
		testcase_io_lib)

add_test(NAME "Filter-SPF"
		COMMAND testcase_filter_spf)

add_executable(testcase_filter_wildcardns
		filter_wildcardns_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/filters/wildcardns.c
)
target_link_libraries(testcase_filter_nomail
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)
add_test(NAME "Filter-WildcardNS"
		COMMAND testcase_filter_wildcardns)

add_executable(testcase_vpop_control
		vpop_control_test.c)
target_link_libraries(testcase_vpop_control
		Qsmtpd_user_vpopm
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)
add_test(NAME "VPop_control"
		COMMAND testcase_vpop_control
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(testcase_getsetting
		getsetting_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/backends/user_vpopm/getfile.c)
target_link_libraries(testcase_getsetting
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)
add_test(NAME "Getsetting"
		COMMAND testcase_getsetting)

add_executable(testcase_netio
		netio_test.c)
target_link_libraries(testcase_netio
		qsmtp_io_lib)

add_executable(test_netio_client
		netio_test_client.c)

add_test(NAME "NetIO"
		COMMAND testcase_netio $<TARGET_FILE:test_netio_client>)

add_executable(testcase_getmxlist
		getmxlist_test.c
		${CMAKE_SOURCE_DIR}/qremote/conn.c)

target_link_libraries(testcase_getmxlist
		testcase_io_lib
		qsmtp_lib
		${MEMCHECK_LIBRARIES})

add_test(NAME "getmxlist"
		COMMAND testcase_getmxlist)

add_executable(testcase_getmxlistv4only
		getmxlist_test.c
		${CMAKE_SOURCE_DIR}/lib/dns_helpers.c
		${CMAKE_SOURCE_DIR}/qremote/conn.c)

target_link_libraries(testcase_getmxlistv4only
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

set_target_properties(testcase_getmxlistv4only PROPERTIES
		COMPILE_DEFINITIONS IPV4ONLY)

add_test(NAME "getmxlist_IPv4_only"
		COMMAND testcase_getmxlistv4only)

add_executable(testcase_tryconn
		tryconn_test.c
		${CMAKE_SOURCE_DIR}/qremote/conn.c)

target_link_libraries(testcase_tryconn
		testcase_io_lib
		qsmtp_lib
		${MEMCHECK_LIBRARIES})

add_test(NAME "tryconn"
		COMMAND testcase_tryconn)

add_executable(testcase_tryconnv4only
		tryconn_test.c
		${CMAKE_SOURCE_DIR}/qremote/conn.c)

set_target_properties(testcase_tryconnv4only PROPERTIES
		COMPILE_DEFINITIONS IPV4ONLY)

target_link_libraries(testcase_tryconnv4only
		testcase_io_lib
		qsmtp_lib
		${MEMCHECK_LIBRARIES})

add_test(NAME "tryconn_IPv4_only"
		COMMAND testcase_tryconnv4only)

add_executable(testcase_connmx
		connmx_test.c
		${CMAKE_SOURCE_DIR}/qremote/conn_mx.c)

target_link_libraries(testcase_connmx
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

add_test(NAME "Qremote_connect_mx"
		COMMAND testcase_connmx)

add_executable(testcase_envelope
		envelope_test.c
		${CMAKE_SOURCE_DIR}/qremote/envelope.c)

target_link_libraries(testcase_envelope
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

add_test(NAME "Qremote_envelope_size_mime7"
		COMMAND testcase_envelope "0009:Z2s2" foo@example.net bar@example.com
		"MAIL FROM:<foo@example.net> SIZE=12345 BODY=7BIT\n|RCPT TO:<bar@example.com>\n")
add_test(NAME "Qremote_envelope_size_mime7_pipeline"
		COMMAND testcase_envelope "000b:Z2s2" foo@example.net bar@example.com
		"MAIL FROM:<foo@example.net> SIZE=12345 BODY=7BIT\nRCPT TO:<bar@example.com>\n")
add_test(NAME "Qremote_envelope_size_mime8"
		COMMAND testcase_envelope "1009:Z2s2" foo@example.net bar@example.com
		"MAIL FROM:<foo@example.net> SIZE=12345 BODY=8BITMIME\n|RCPT TO:<bar@example.com>\n")
add_test(NAME "Qremote_envelope_size_mime8_pipeline"
		COMMAND testcase_envelope "100b:Z2s2" foo@example.net bar@example.com
		"MAIL FROM:<foo@example.net> SIZE=12345 BODY=8BITMIME\nRCPT TO:<bar@example.com>\n")
add_test(NAME "Qremote_envelope_noext"
		COMMAND testcase_envelope "0000:Z2s2" foo@example.net bar@example.com
		"MAIL FROM:<foo@example.net>\n|RCPT TO:<bar@example.com>\n")
add_test(NAME "Qremote_envelope_pipeline"
		COMMAND testcase_envelope "0002:Z2s2" foo@example.net bar@example.com
		"MAIL FROM:<foo@example.net>\nRCPT TO:<bar@example.com>\n")
add_test(NAME "Qremote_envelope_pipeline_errMail"
		COMMAND testcase_envelope "0102:Z505" foo@example.net bar@example.com
		"MAIL FROM:<foo@example.net>\nRCPT TO:<bar@example.com>\n")
add_test(NAME "Qremote_envelope_errMail"
		COMMAND testcase_envelope "0100:Z5" foo@example.net
		"MAIL FROM:<foo@example.net>\n")
add_test(NAME "Qremote_envelope_pipeline_errRcpt"
		COMMAND testcase_envelope "0102:Z2s5" foo@example.net bar@example.com
		"MAIL FROM:<foo@example.net>\nRCPT TO:<bar@example.com>\n")
add_test(NAME "Qremote_envelope_pipeline_errRcpt2"
		COMMAND testcase_envelope "0002:Z2s2s5" foo@example.net bar@example.com baz@example.com
		"MAIL FROM:<foo@example.net>\nRCPT TO:<bar@example.com>\n|RCPT TO:<baz@example.com>\n")
add_test(NAME "Qremote_envelope_pipeline_errRcpt1of2"
		COMMAND testcase_envelope "0002:Z2s5s2" foo@example.net bar@example.com baz@example.com
		"MAIL FROM:<foo@example.net>\nRCPT TO:<bar@example.com>\n|RCPT TO:<baz@example.com>\n")
add_test(NAME "Qremote_envelope_pipeline_errRcpt1of3"
		COMMAND testcase_envelope "0002:Z2s5s2s2" foo@example.net bar@example.com baz@example.com bat@example.com
		"MAIL FROM:<foo@example.net>\nRCPT TO:<bar@example.com>\n|RCPT TO:<baz@example.com>\nRCPT TO:<bat@example.com>\n")
add_test(NAME "Qremote_envelope_pipeline_errRcpt1of4"
		COMMAND testcase_envelope "0002:Z2s5s2s2s2" foo@example.net bar@example.com baz@example.com bat@example.com but@example.com
		"MAIL FROM:<foo@example.net>\nRCPT TO:<bar@example.com>\n|RCPT TO:<baz@example.com>\nRCPT TO:<bat@example.com>\nRCPT TO:<but@example.com>\n")
add_test(NAME "Qremote_envelope_3rcpt"
		COMMAND testcase_envelope "0000:Z2s2s2" foo@example.net bar@example.com baz@example.com
		"MAIL FROM:<foo@example.net>\n|RCPT TO:<bar@example.com>\n|RCPT TO:<baz@example.com>\n")
add_test(NAME "Qremote_envelope_pipeline_5rcpt"
		COMMAND testcase_envelope "0002:Z2s2s2s2s2s2" foo@example.net bar@example.com baz@example.com bat@example.com but@example.com bot@example.com
		"MAIL FROM:<foo@example.net>\nRCPT TO:<bar@example.com>\n|RCPT TO:<baz@example.com>\nRCPT TO:<bat@example.com>\nRCPT TO:<but@example.com>\n|RCPT TO:<bot@example.com>\n")

# This is a brute force test just to get some "real" coverage on the file.
# It will always fail, either because ${AUTOQMAIL} doesn't exist or doesn't
# have the proper configuration files or simply because we do not pass it
# any arguments.
add_test(NAME "Qremote_no_stdin"
		COMMAND stdin-exec "" $<TARGET_FILE:Qremote> invalid.invalid from@invalid.invalid to@invalid.invalid)
set_tests_properties(Qremote_no_stdin PROPERTIES
		PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}Z4.3.0 internal error: can't fstat\\(\\) input\n")
add_test(NAME "Qremote_noinput_noargs"
		COMMAND stdin-exec "" $<TARGET_FILE:Qremote>)

# In case we have a proper configuration this may even check some more lines.
# Since the destination address should really not exists this will still fail.
add_test(NAME "Qremote_to_invalid"
		COMMAND stdin-exec "${CMAKE_CURRENT_LIST_FILE}" $<TARGET_FILE:Qremote> invalid.invalid from@invalid.invalid to@invalid.invalid)
add_test(NAME "Qremote_to_null_MX"
		COMMAND stdin-exec "${CMAKE_CURRENT_LIST_FILE}" $<TARGET_FILE:Qremote> example.com from@example.com to@example.com)
add_test(NAME "Qremote_to_localhost"
		COMMAND stdin-exec "${CMAKE_CURRENT_LIST_FILE}" $<TARGET_FILE:Qremote> "[127.0.0.1]" "from@invalid.invalid" "to@[127.0.0.1]")
if (NOT IPV4ONLY)
	add_test(NAME "Qremote_to_localhost6"
			COMMAND stdin-exec "${CMAKE_CURRENT_LIST_FILE}" $<TARGET_FILE:Qremote> "[::1]" "from@invalid.invalid" "to@[::1]")
endif ()
add_test(NAME "Qremote_to_bad_expression"
		COMMAND stdin-exec "${CMAKE_CURRENT_LIST_FILE}" $<TARGET_FILE:Qremote> "[127.0" "from@invalid.invalid" "to@localhost")
add_test(NAME "Qremote_to_bad_expression2"
		COMMAND stdin-exec "${CMAKE_CURRENT_LIST_FILE}" $<TARGET_FILE:Qremote> "[127.0.a.v]" "from@invalid.invalid" "to@localhost")
add_test(NAME "Qremote_no_mmap"
		COMMAND stdin-exec "s" $<TARGET_FILE:Qremote> "[192.0.2.19]" "from@invalid.invalid" "to@localhost")
set_tests_properties(Qremote_no_mmap PROPERTIES
		PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}Z4.3.0 internal error: can't mmap\\(\\) input\n")

add_executable(stdin-exec stdin-exec.c)

if (AUTOQMAIL_FROM_TESTSUITE)
	set_tests_properties(Qremote_noinput_noargs PROPERTIES
			PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}Z4.3.0 internal error: Qremote called with invalid arguments\n")
	set_tests_properties(Qremote_to_invalid PROPERTIES
			PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}Z4\\.4\\.3 cannot find a mail exchanger for invalid\\.invalid\n")
	set_tests_properties(Qremote_to_null_MX PROPERTIES
			PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}D5\\.1\\.10 only null MX exists for example.com\n")
	set_tests_properties(Qremote_to_localhost PROPERTIES
			PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}Z4\\.4\\.3 all mail exchangers for \\[127\\.0\\.0\\.1\\] point back to me\n")
	if (NOT IPV4ONLY)
		set_tests_properties(Qremote_to_localhost6 PROPERTIES
				PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}Z4\\.4\\.3 all mail exchangers for \\[::1\\] point back to me\n")
	endif ()
	set_tests_properties(Qremote_to_bad_expression Qremote_to_bad_expression2 PROPERTIES
			PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}Z4\\.3\\.0 parse error in first argument\n")
else ()
	if (NOT IPV4ONLY)
		set(V6TESTS Qremote_to_localhost6)
	endif ()
	set_tests_properties(Qremote_noinput_noargs Qremote_to_invalid
			Qremote_to_null_MX Qremote_to_localhost
			Qremote_to_bad_expression Qremote_to_bad_expression2
			${V6TESTS}
			PROPERTIES
			PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}Z[45]\\.[0-9]\\.[0-9] ")
endif ()

add_executable(testcase_qsdata
		qsdata_test.c
)

target_link_libraries(testcase_qsdata
		testcase_io_lib
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
		${OPENSSL_LIBRARIES}
)

add_test(NAME "Qsmtpd_data"
		COMMAND testcase_qsdata)

# Another brute force test, this time for Qsmtpd
set(TEST_SEQUENCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/quit.cmake")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_quit.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_quit.cmake" @ONLY)
add_test(NAME "Qsmtpd_quit"
		COMMAND "${CMAKE_COMMAND}"
				-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_quit.cmake")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_quit_no_ips.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_quit_no_ips.cmake" @ONLY)
add_test(NAME "Qsmtpd_quit_no_ips"
		COMMAND "${CMAKE_COMMAND}"
				-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_quit_no_ips.cmake")

# Do not add \r here, looks like CMake automatically strips it, so just
# assume we are doing it right.
set_tests_properties(Qsmtpd_quit Qsmtpd_quit_no_ips PROPERTIES
		PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}${QSMTPD_GREETING_LINE}${QSMTPD_QUIT_LINE}$")

set(TEST_SEQUENCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/postmaster_rset.cmake")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_quit.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_quit_postmaster.cmake" @ONLY)
add_test(NAME "Qsmtpd_postmaster_rset"
		COMMAND "${CMAKE_COMMAND}"
				-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_quit_postmaster.cmake")

# Do not add \r here, looks like CMake automatically strips it, so just
# assume we are doing it right.
set_tests_properties(Qsmtpd_postmaster_rset PROPERTIES
		PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}${QSMTPD_GREETING_LINE}${QSMTPD_HELO_RESPONSE}250 2\\.0\\.0 ok\n250 2\\.0\\.0 ok\n250-[^\n ]*\n250-ENHANCEDSTATUSCODES\n250-PIPELINING\n250-8BITMIME\n(.*\n)?250 SIZE( [0-9]+)?\n250 2\\.1\\.5 sender <> is syntactically correct\n250 2\\.1\\.0 recipient <postmaster> OK\n250 2\\.0\\.0 ok\n503 5\\.5\\.1 Bad sequence of commands\n${QSMTPD_QUIT_LINE}$")

set(TEST_SEQUENCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/bounce_multi_rcpt.cmake")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_quit.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_bad_bounce.cmake" @ONLY)
add_test(NAME "Qsmtpd_bad_bounce"
		COMMAND "${CMAKE_COMMAND}"
				-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_bad_bounce.cmake")

# Do not add \r here, looks like CMake automatically strips it, so just
# assume we are doing it right.
set_tests_properties(Qsmtpd_bad_bounce PROPERTIES
		PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}${QSMTPD_GREETING_LINE}250-[^\n ]*\n250-ENHANCEDSTATUSCODES\n250-PIPELINING\n250-8BITMIME\n(.*\n)?250 SIZE( [0-9]+)?\n250 2\\.1\\.5 sender <> is syntactically correct\n250 2\\.1\\.0 recipient <postmaster> OK\n550 5\\.5\\.3 bounce messages must not have more than one recipient\n554 5\\.1\\.1 no valid recipients\n${QSMTPD_QUIT_LINE}$")

set(TEST_SEQUENCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cmd_args.cmake")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_quit.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_cmd_args.cmake" @ONLY)
add_test(NAME "Qsmtpd_cmd_args"
		COMMAND "${CMAKE_COMMAND}"
				-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_cmd_args.cmake")
# Do not add \r here, looks like CMake automatically strips it, so just
# assume we are doing it right.
set_tests_properties(Qsmtpd_cmd_args PROPERTIES
		PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}${QSMTPD_GREETING_LINE}${QSMTPD_HELO_RESPONSE}${QSMTPD_HELO_RESPONSE}500 5\\.5\\.2 command syntax error\n250-[^\n ]*\n250-ENHANCEDSTATUSCODES\n250-PIPELINING\n250-8BITMIME\n(.*\n)?250 SIZE( [0-9]+)?\n501 5\\.5\\.2 unrecognized command parameter\n250 2\\.1\\.5 sender <> is syntactically correct\n500 5\\.5\\.2 command syntax error\n501 5\\.1\\.3 domain of mail address is syntactically incorrect\n250 2\\.0\\.0 ok\n250 2\\.1\\.5 sender <> is syntactically correct\n(500 5\\.5\\.2 command syntax error\n250 2\\.0\\.0 ok\n)+500-5\\.5\\.2 line too long\n500-5\\.5\\.2 This is usually a bug in your mail client\n500 5\\.5\\.2 Try to use a different encoding like quoted-printable for this mail.\n250 2.0.0 ok\n501 5\\.1\\.3 domain of mail address is syntactically incorrect\n250 2\\.0\\.0 ok\n500 5\\.5\\.2 command syntax error\n503 5\\.5\\.1 SMTP command sent after end of PIPELINING command group\n503 5\\.5\\.1 Bad sequence of commands\n${QSMTPD_QUIT_LINE}$")

set(TEST_SEQUENCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_bad_args.cmake")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_quit.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_bad_args.cmake" @ONLY)
add_test(NAME "Qsmtpd_bad_args"
		COMMAND "${CMAKE_COMMAND}"
				-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_bad_args.cmake")
# Do not add \r here, looks like CMake automatically strips it, so just
# assume we are doing it right.
set_tests_properties(Qsmtpd_bad_args PROPERTIES
		PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}${QSMTPD_GREETING_LINE}500 5\\.5\\.2 command syntax error\n250-[^\n ]*\n250-ENHANCEDSTATUSCODES\n250-PIPELINING\n250-8BITMIME\n(.*\n)?250 SIZE( [0-9]+)?\n500 5\\.5\\.2 command syntax error\n252 2\\.1\\.5 send some mail, I'll do my very best\n500 5\\.5\\.2 command syntax error\n(500 5\\.5\\.2 command syntax error\n250 2\\.0\\.0 ok\n)+250 [^\n]+\n250 2\\.1\\.5 sender <someone@example.invalid> is syntactically correct\n${QSMTPD_QUIT_LINE}$")

set(TEST_SEQUENCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/bad_pipelining.cmake")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_quit.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_bad_pipelining.cmake" @ONLY)
add_test(NAME "Qsmtpd_bad_pipelining"
		COMMAND "${CMAKE_COMMAND}"
				-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_bad_pipelining.cmake")
# Do not add \r here, looks like CMake automatically strips it, so just
# assume we are doing it right.
set_tests_properties(Qsmtpd_bad_pipelining PROPERTIES
		PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}${QSMTPD_GREETING_LINE}${QSMTPD_HELO_RESPONSE}550 5\\.5\\.0 you must wait for my reply\n503 5\\.5\\.1 Bad sequence of commands\n503 5\\.5\\.1 Bad sequence of commands\n${QSMTPD_QUIT_LINE}$")

set(TEST_LOCAL_IP4 "203.0.113.42")
set(TEST_REMOTE_IP4 "203.0.113.24")
set(TEST_LOCAL_IP6 "2001:db8::42:42")
set(TEST_REMOTE_IP6 "2001:db8::24:24")

# on an installed system the user could have disabled AUTH without STARTTLS
if (NOT EXISTS ${AUTOQMAIL}/control/forcesslauth)
	set(TEST_SEQUENCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/no_auth_submission.cmake")
	configure_file("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_submission.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_no_auth_submission.cmake" @ONLY)
	add_test(NAME "Qsmtpd_no_auth_submission"
			COMMAND "${CMAKE_COMMAND}"
					-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_no_auth_submission.cmake")
	# Do not add \r here, looks like CMake automatically strips it, so just
	# assume we are doing it right.
	set_tests_properties(Qsmtpd_no_auth_submission PROPERTIES
			PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}${QSMTPD_GREETING_LINE}(250-[^\n]+\n)+250-AUTH [^\n]+\n(250-[^\n]+\n)*250 SIZE( [0-9]+)?\n550 5.7.1 authentication required\n${QSMTPD_QUIT_LINE}$")
endif ()

set(TEST_LOCAL_IP4 "192.0.2.19")
set(TEST_REMOTE_IP4 "203.0.113.24")
set(TEST_LOCAL_IP6 "2001:db8::123")
set(TEST_REMOTE_IP6 "2001:db8::24:24")

set(TEST_SEQUENCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_more_commands.cmake")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_submission.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_more_commands.cmake" @ONLY)
add_test(NAME "Qsmtpd_more_commands"
		COMMAND "${CMAKE_COMMAND}"
				-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_more_commands.cmake")

# Do not add \r here, looks like CMake automatically strips it, so just
# assume we are doing it right.
if (AUTOQMAIL_FROM_TESTSUITE)
	# require STARTTLS in the testsuite, the certificates were copied at the proper place
	set_tests_properties(Qsmtpd_more_commands PROPERTIES
			PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}${QSMTPD_GREETING_LINE}(250-[^\n]+\n)+250-AUTH [^\n]+\n(250-[A-Z8][^\n]+\n)*250-STARTTLS\n250 SIZE 1024\n235 2\\.7\\.0 ok, go ahead\n452 4\\.3\\.1 Requested action not taken: insufficient system storage\n${QSMTPD_HELO_RESPONSE}503 5.5.1 Bad sequence of commands\n${QSMTPD_QUIT_LINE}$")
else ()
	# when using the system control directory ignore if STARTTLS is given or not
	# AUTH without STARTTLS may be permitted or not
	# databytes may be set as small as in this testcase (unlikely), set to a higher value or not set at all
	set_tests_properties(Qsmtpd_more_commands PROPERTIES
			PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}${QSMTPD_GREETING_LINE}(250-[^\n]+\n)+250 SIZE( [0-9]+)?\n(235 2\\.7\\.0 ok, go ahead\n(250 2\\.1\\.5 sender <> is syntactically correct|452 4\\.3\\.1 Requested action not taken: insufficient system storage)|503 5\\.5\\.1 Bad sequence of commands\n550 5\\.7\\.1 authentication required)\n${QSMTPD_HELO_RESPONSE}503 5.5.1 Bad sequence of commands\n${QSMTPD_QUIT_LINE}$")

endif ()

set(TEST_SEQUENCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/broken_helo.cmake")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/Qsmtpd_submission.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_broken_helo.cmake" @ONLY)
add_test(NAME "Qsmtpd_broken_helo"
		COMMAND "${CMAKE_COMMAND}"
				-P "${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd_broken_helo.cmake")
# Do not add \r here, looks like CMake automatically strips it, so just
# assume we are doing it right.
set_tests_properties(Qsmtpd_broken_helo PROPERTIES
		PASS_REGULAR_EXPRESSION "^${PROFILE_MSG}${QSMTPD_GREETING_LINE}(500 5\\.5\\.2 command syntax error\n250 2.0.0 ok\n)+${QSMTPD_QUIT_LINE}$")

add_executable(testcase_ipme
		ipme_test.c)
target_link_libraries(testcase_ipme
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)
add_test(NAME "IPme"
		COMMAND testcase_ipme)

add_executable(testcase_ehlo_parsing
		ehlo_test.c
		${CMAKE_SOURCE_DIR}/qremote/greeting.c
)
target_link_libraries(testcase_ehlo_parsing
		${MEMCHECK_LIBRARIES}
		testcase_io_lib
)
add_test(NAME "EHLO_parsing"
		COMMAND testcase_ehlo_parsing)


add_executable(testcase_vpop_vget_dir
		vpop_vget_dir_test.c
		cdb_entries.h)
target_link_libraries(testcase_vpop_vget_dir
		Qsmtpd_user_vpopm
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "VPop_vget_dir"
		COMMAND testcase_vpop_vget_dir "${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(testcase_qrclient
		qrclient_test.c
		../qremote/client.c
		../qremote/status.c
)
target_link_libraries(testcase_qrclient
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "Qrclient"
		COMMAND testcase_qrclient)

add_executable(testcase_qrreply
		qrreply_test.c
		../qremote/reply.c
)
target_link_libraries(testcase_qrreply
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "Qrreply"
		COMMAND testcase_qrreply)

add_executable(testcase_queue_envelope
		queue_envelope_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/queue.c
)
target_link_libraries(testcase_queue_envelope
		qsmtp_lib
		testcase_io_lib
		${OPENSSL_LIBRARIES}
)

add_test(NAME "Queue_envelope"
		COMMAND testcase_queue_envelope)

add_executable(testcase_cmd_rcpt
		cmd_rcpt_test.c
		${CMAKE_SOURCE_DIR}/lib/fmt.c
		${CMAKE_SOURCE_DIR}/qsmtpd/commands.c)
target_link_libraries(testcase_cmd_rcpt
		testcase_io_lib)

add_test(NAME "Qsmtpd_cmd_RCPT"
		COMMAND testcase_cmd_rcpt)

add_executable(testcase_cmd_from
		cmd_from_test.c
		${CMAKE_SOURCE_DIR}/lib/dns_helpers.c
		${CMAKE_SOURCE_DIR}/lib/fmt.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrparse.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrsyntax.c
		${CMAKE_SOURCE_DIR}/qsmtpd/commands.c
		${CMAKE_SOURCE_DIR}/qsmtpd/xtext.c)
target_link_libraries(testcase_cmd_from
		testcase_io_lib)

add_test(NAME "Qsmtpd_cmd_FROM"
		COMMAND testcase_cmd_from)

add_executable(testcase_ssl_pp
		ssl_pp.c
		${CMAKE_SOURCE_DIR}/qremote/reply.c
		${CMAKE_SOURCE_DIR}/qremote/starttlsr.c
		${CMAKE_SOURCE_DIR}/qsmtpd/starttls.c
		${CMAKE_SOURCE_DIR}/lib/tls.c
		${CMAKE_SOURCE_DIR}/lib/netio.c
		${CMAKE_SOURCE_DIR}/lib/ssl_timeoutio.c
)

target_link_libraries(testcase_ssl_pp
		qsmtp_lib
		${OPENSSL_LIBRARIES}
)

foreach(_ssl_test IN ITEMS simple simple_clc tlsclients_dir
		simple_clc_tlsclients simple_clc_clientca simple_clientca
		relay_no_name relay_other relay_multi_first relay_multi_last
		relay_withca
		matching_servercert matching_wildcard
		nonmatching_servercert nonmatching_wildcard
		SubjAN_match SubjAN2_match SubjAN_cn
		servercert_no_name expired)
	set(_tgt_dir "${CMAKE_CURRENT_BINARY_DIR}/ssl_pp/${_ssl_test}")
	file(MAKE_DIRECTORY "${_tgt_dir}/control")

	foreach(_pem IN ITEMS rsa2048 dh2048)
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/${_pem}.pem
				"${_tgt_dir}/control/${_pem}.pem" COPYONLY)
	endforeach()

	unset(_ssl_test_arg)
	unset(_ssl_client_key)
	unset(_ssl_server_key)
	if (_ssl_test STREQUAL "simple")
		set(_ssl_server_key "valid1024.key")
	elseif (_ssl_test STREQUAL "simple_clc")
		set(_ssl_client_key "valid1024.key")
		set(_ssl_server_key "valid1024.key")
	elseif (_ssl_test STREQUAL "tlsclients_dir")
		set(_ssl_server_key "valid1024.key")
		file(MAKE_DIRECTORY "${_tgt_dir}/control/tlsclients")
		set(_ssl_test_arg "-sEISDIR")
	elseif (_ssl_test STREQUAL "relay_withca")
		set(_ssl_client_key "withca.key")
		set(_ssl_server_key "valid1024.key")
		file(WRITE "${_tgt_dir}/control/tlsclients" "testcert.example.org\n")
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/test-ca.crt
				"${_tgt_dir}/control/clientca.pem" COPYONLY)
		set(_ssl_test_arg "-s1")
	elseif (_ssl_test STREQUAL "simple_clc_tlsclients" OR _ssl_test STREQUAL "simple_clc_clientca")
		set(_ssl_client_key "valid1024.key")
		set(_ssl_server_key "valid1024.key")
		file(WRITE "${_tgt_dir}/control/tlsclients" "testcert.example.org\n")
		if (_ssl_test STREQUAL "simple_clc_clientca")
			configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/valid1024.crt
					"${_tgt_dir}/control/clientca.pem" COPYONLY)
			set(_ssl_test_arg "-s1")
		endif ()
	elseif (_ssl_test STREQUAL "simple_clientca")
		set(_ssl_server_key "valid1024.key")
		file(WRITE "${_tgt_dir}/control/tlsclients" "testcert.example.org\n")
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/valid1024.crt
				"${_tgt_dir}/control/clientca.pem" COPYONLY)
	elseif (_ssl_test STREQUAL "relay_no_name")
		set(_ssl_client_key "noname.key")
		set(_ssl_server_key "valid1024.key")
		file(WRITE "${_tgt_dir}/control/tlsclients" "testcert.example.org\n")
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/noname.crt
				"${_tgt_dir}/control/clientca.pem" COPYONLY)
	elseif (_ssl_test STREQUAL "relay_other")
		set(_ssl_client_key "valid1024_san.key")
		set(_ssl_server_key "valid1024.key")
		file(WRITE "${_tgt_dir}/control/tlsclients" "testcert.example.org\n")
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/noname.crt
				"${_tgt_dir}/control/clientca.pem" COPYONLY)
	elseif (_ssl_test STREQUAL "relay_multi_first" OR _ssl_test STREQUAL "relay_multi_last")
		set(_ssl_client_key "valid1024.key")
		set(_ssl_server_key "valid1024.key")
		file(WRITE "${_tgt_dir}/control/tlsclients" "testcert.example.org\n")
		file(READ ${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/noname.crt NONAME_CRT)
		file(READ ${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/valid1024.crt VALID_CRT)
		if (_ssl_test STREQUAL "relay_multi_first")
			file(WRITE "${_tgt_dir}/control/clientca.pem"
				"${VALID_CRT}${NONAME_CRT}")
		else ()
			file(WRITE "${_tgt_dir}/control/clientca.pem"
				"${NONAME_CRT}${VALID_CRT}")
		endif ()
		set(_ssl_test_arg "-s1")
	elseif (_ssl_test STREQUAL "simple_clc_tlsclients")
		set(_ssl_client_key "valid1024.key")
		set(_ssl_server_key "valid1024.key")
		file(WRITE "${_tgt_dir}/control/tlsclients" "testcert.example.org\n")
	elseif (_ssl_test STREQUAL "matching_servercert")
		file(MAKE_DIRECTORY "${_tgt_dir}/control/tlshosts")
		set(_ssl_server_key "valid1024.key")
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/valid1024.crt
				"${_tgt_dir}/control/tlshosts/testcert.example.org.pem" COPYONLY)
	elseif (_ssl_test STREQUAL "matching_wildcard")
		file(MAKE_DIRECTORY "${_tgt_dir}/control/tlshosts")
		set(_ssl_server_key "wildcard1024.key")
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/wildcard1024.crt
				"${_tgt_dir}/control/tlshosts/testcert.example.org.pem" COPYONLY)
	elseif (_ssl_test STREQUAL "nonmatching_servercert")
		file(MAKE_DIRECTORY "${_tgt_dir}/control/tlshosts")
		set(_ssl_server_key "valid1024.key")
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/valid1024.crt
				"${_tgt_dir}/control/tlshosts/testcert.example.net.pem" COPYONLY)
		set(_ssl_test_arg "-ftestcert.example.net" "-lunable to verify testcert.example.net with control/tlshosts/testcert.example.net.pem: Hostname mismatch" "-iEDONE")
	elseif (_ssl_test STREQUAL "nonmatching_wildcard")
		file(MAKE_DIRECTORY "${_tgt_dir}/control/tlshosts")
		set(_ssl_server_key "wildcard1024.key")
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/wildcard1024.crt
				"${_tgt_dir}/control/tlshosts/testcert.example.net.pem" COPYONLY)
		set(_ssl_test_arg "-ftestcert.example.net" "-lunable to verify testcert.example.net with control/tlshosts/testcert.example.net.pem: Hostname mismatch" "-iEDONE")
	elseif (_ssl_test STREQUAL "SubjAN_match")
		file(MAKE_DIRECTORY "${_tgt_dir}/control/tlshosts")
		set(_ssl_server_key "valid1024_san.key")
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/valid1024_san.crt
				"${_tgt_dir}/control/tlshosts/testcert.example.org.pem" COPYONLY)
	elseif (_ssl_test STREQUAL "SubjAN2_match")
		file(MAKE_DIRECTORY "${_tgt_dir}/control/tlshosts")
		set(_ssl_server_key "valid1024_san2.key")
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/valid1024_san2.crt
				"${_tgt_dir}/control/tlshosts/testcert.example.org.pem" COPYONLY)
	elseif (_ssl_test STREQUAL "SubjAN_cn")
		file(MAKE_DIRECTORY "${_tgt_dir}/control/tlshosts")
		set(_ssl_server_key "valid1024_san_cn.key")
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/valid1024_san_cn.crt
				"${_tgt_dir}/control/tlshosts/testcert.example.org.pem" COPYONLY)
		set(_ssl_test_arg "-lunable to verify testcert.example.org with control/tlshosts/testcert.example.org.pem: Hostname mismatch" "-iEDONE")
	elseif (_ssl_test STREQUAL "servercert_no_name")
		file(MAKE_DIRECTORY "${_tgt_dir}/control/tlshosts")
		set(_ssl_server_key "noname.key")
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/noname.crt
				"${_tgt_dir}/control/tlshosts/testcert.example.org.pem" COPYONLY)
		set(_ssl_test_arg "-lunable to verify testcert.example.org with control/tlshosts/testcert.example.org.pem: Hostname mismatch" "-iEDONE")
	elseif (_ssl_test STREQUAL "expired")
		file(MAKE_DIRECTORY "${_tgt_dir}/control/tlshosts")
		set(_ssl_server_key "expired.key")
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/expired.crt
				"${_tgt_dir}/control/tlshosts/testcert.example.org.pem" COPYONLY)
		set(_ssl_test_arg "-lunable to verify testcert.example.org with control/tlshosts/testcert.example.org.pem: certificate has expired" "-iEDONE")
	endif ()

	if (_ssl_client_key)
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/${_ssl_client_key}
				"${_tgt_dir}/control/clientcert.pem" COPYONLY)
	endif ()
	if (_ssl_server_key)
		configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssl_pp/${_ssl_server_key}
				"${_tgt_dir}/control/servercert.pem" COPYONLY)
	endif ()

	add_test(NAME "SSL_pp_${_ssl_test}"
			COMMAND testcase_ssl_pp ${_ssl_test_arg}
			WORKING_DIRECTORY "${_tgt_dir}")
endforeach()

# something changed durin OpenSSL cycle there and the certificate signatures are not accepted anymore
foreach(_ssl_test IN ITEMS simple_clc_clientca relay_multi_first relay_multi_last
		relay_withca)
	set_tests_properties(SSL_pp_${_ssl_test} PROPERTIES WILL_FAIL TRUE)
endforeach()

add_subdirectory(smtproutes)
add_subdirectory(starttlsr)
add_subdirectory(user_exists)
