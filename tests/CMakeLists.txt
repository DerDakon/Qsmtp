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

add_executable(testcase_control
		control_test.c)

target_link_libraries(testcase_control
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

add_executable(testcase_base64
		base64_test.c)

target_link_libraries(testcase_base64
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})


add_executable(testcase_cdb
		cdb_test.c
		cdb_entries.h)
target_link_libraries(testcase_cdb
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

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

add_executable(testcase_auth_be_cp
		auth_be_cp_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/child.c
)

if (HAS_PIPE2)
	set_property(SOURCE ${CMAKE_SOURCE_DIR}/qsmtpd/child.c APPEND PROPERTY COMPILE_DEFINITIONS HAS_PIPE2)
endif ()

target_link_libraries(testcase_auth_be_cp
		Qsmtpd_auth_checkpassword
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

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

add_executable(testcase_matchnet
		matchnet_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/antispam.c)

target_link_libraries(testcase_matchnet
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_executable(testcase_hostname
		hostname_test.c)

target_link_libraries(testcase_hostname
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_executable(testcase_xtext
		xtext_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrsyntax.c
		${CMAKE_SOURCE_DIR}/qsmtpd/xtext.c)

target_link_libraries(testcase_xtext
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

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

add_executable(testcase_qrbdat
		qrbdat_test.c
		${CMAKE_SOURCE_DIR}/qremote/qrbdat.c
)

target_link_libraries(testcase_qrbdat
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_executable(testcase_fmt
		fmt_test.c)
target_link_libraries(testcase_fmt
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_executable(testcase_addrparse
		addrparse_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrparse.c)
target_link_libraries(testcase_addrparse
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_executable(testcase_addrsyntax
		addrsyntax_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/addrsyntax.c)
target_link_libraries(testcase_addrsyntax
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_executable(testcase_mmap
		mmap_test.c)
target_link_libraries(testcase_mmap
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_executable(testcase_dns
		dns_test.c)
target_link_libraries(testcase_dns
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_executable(testcase_qdns
		qdns_test.c
		../lib/qdns.c)
target_link_libraries(testcase_qdns
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
)

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

add_executable(testcase_mime
		mime_test.c
		${CMAKE_SOURCE_DIR}/qremote/mime.c
)
target_link_libraries(testcase_mime
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_executable(testcase_mime_boundary
		mime_boundary_test.c
		${CMAKE_SOURCE_DIR}/qremote/mime.c
)
target_link_libraries(testcase_mime_boundary
# 		qsmtp_lib
# 		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_executable(testcase_antispam
		antispam_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/antispam.c
)
target_link_libraries(testcase_antispam
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

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

add_executable(testcase_filter_spf
		filter_spf.c
		${CMAKE_SOURCE_DIR}/qsmtpd/filters/spf.c
		${CMAKE_SOURCE_DIR}/qsmtpd/filters/rcpt_filters.c
)
target_link_libraries(testcase_filter_spf
		qsmtp_lib
		testcase_io_lib)


add_executable(testcase_filter_wildcardns
		filter_wildcardns_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/filters/wildcardns.c
)
target_link_libraries(testcase_filter_nomail
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_executable(testcase_vpop_control
		vpop_control_test.c)
target_link_libraries(testcase_vpop_control
		Qsmtpd_user_vpopm
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_executable(testcase_getsetting
		getsetting_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/backends/user_vpopm/getfile.c)
target_link_libraries(testcase_getsetting
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_executable(testcase_netio
		netio_test.c)
target_link_libraries(testcase_netio
		qsmtp_io_lib)

add_executable(test_netio_client
		netio_test_client.c)


add_executable(testcase_getmxlist
		getmxlist_test.c
		${CMAKE_SOURCE_DIR}/qremote/conn.c)

target_link_libraries(testcase_getmxlist
		testcase_io_lib
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
		${CMAKE_SOCKET_LIB}
)

add_executable(testcase_getmxlistv4only
		getmxlist_test.c
		${CMAKE_SOURCE_DIR}/lib/dns_helpers.c
		${CMAKE_SOURCE_DIR}/qremote/conn.c)

target_link_libraries(testcase_getmxlistv4only
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
		${CMAKE_SOCKET_LIB}
)

set_target_properties(testcase_getmxlistv4only PROPERTIES
		COMPILE_DEFINITIONS IPV4ONLY)

add_executable(testcase_tryconn
		tryconn_test.c
		${CMAKE_SOURCE_DIR}/qremote/conn.c)

target_link_libraries(testcase_tryconn
		testcase_io_lib
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
		${CMAKE_SOCKET_LIB}
)

add_executable(testcase_tryconnv4only
		tryconn_test.c
		${CMAKE_SOURCE_DIR}/qremote/conn.c)

set_target_properties(testcase_tryconnv4only PROPERTIES
		COMPILE_DEFINITIONS IPV4ONLY)

target_link_libraries(testcase_tryconnv4only
		testcase_io_lib
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
		${CMAKE_SOCKET_LIB}
)

add_executable(testcase_connmx
		connmx_test.c
		${CMAKE_SOURCE_DIR}/qremote/conn_mx.c)

target_link_libraries(testcase_connmx
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

add_executable(testcase_envelope
		envelope_test.c
		${CMAKE_SOURCE_DIR}/qremote/envelope.c)

target_link_libraries(testcase_envelope
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES})

add_executable(stdin-exec stdin-exec.c)
target_link_libraries(stdin-exec
		${CMAKE_SOCKET_LIB}
)

add_executable(testcase_qsdata
		qsdata_test.c
)

if (NOT HAS_GMTOFF)
	set_property(SOURCE qsdata_test.c APPEND PROPERTY COMPILE_DEFINITIONS NO_GMTOFF)
endif ()

target_link_libraries(testcase_qsdata
		testcase_io_lib
		qsmtp_lib
		${MEMCHECK_LIBRARIES}
		OpenSSL::SSL
)

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

set(TEST_LOCAL_IP4 "192.0.2.19")
set(TEST_REMOTE_IP4 "203.0.113.24")
set(TEST_LOCAL_IP6 "2001:db8::123")
set(TEST_REMOTE_IP6 "2001:db8::24:24")

add_executable(testcase_ipme
		ipme_test.c)
target_link_libraries(testcase_ipme
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
		${CMAKE_SOCKET_LIB}
)

add_executable(testcase_ehlo_parsing
		ehlo_test.c
		${CMAKE_SOURCE_DIR}/qremote/greeting.c
)
target_link_libraries(testcase_ehlo_parsing
		${MEMCHECK_LIBRARIES}
		testcase_io_lib
)

add_executable(testcase_vpop_vget_dir
		vpop_vget_dir_test.c
		cdb_entries.h)
target_link_libraries(testcase_vpop_vget_dir
		Qsmtpd_user_vpopm
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_executable(testcase_qrclient
		qrclient_test.c
		../qremote/client.c
		../qremote/status.c
)
target_link_libraries(testcase_qrclient
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_executable(testcase_qrreply
		qrreply_test.c
		../qremote/reply.c
)
target_link_libraries(testcase_qrreply
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_executable(testcase_queue_envelope
		queue_envelope_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/queue.c
)
target_link_libraries(testcase_queue_envelope
		qsmtp_lib
		testcase_io_lib
		OpenSSL::SSL
)

add_executable(testcase_cmd_rcpt
		cmd_rcpt_test.c
		${CMAKE_SOURCE_DIR}/lib/fmt.c
		${CMAKE_SOURCE_DIR}/qsmtpd/commands.c)
target_link_libraries(testcase_cmd_rcpt
		testcase_io_lib)

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
