configure_file("${CMAKE_CURRENT_SOURCE_DIR}/tlsclientciphers_good/control/clientcert.pem"
	"${CMAKE_BINARY_DIR}/var/qmail/control/servercert.pem.2001:db8::123:587")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/tlsclientciphers_good/control/clientcert.pem"
	"${CMAKE_BINARY_DIR}/var/qmail/control/servercert.pem.192.0.2.19:587")

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/..")

add_executable(testcase_starttlsr
		starttlsr_test.c
		../../lib/ssl_timeoutio.c
		../../qremote/starttlsr.c)
target_link_libraries(testcase_starttlsr
		testcase_io_lib
		qsmtp_lib
		${OPENSSL_LIBRARIES}
)

add_test(NAME "STARTTLSr"
		COMMAND testcase_starttlsr
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tlsclientciphers_good")

set_tests_properties(STARTTLSr PROPERTIES
		PASS_REGULAR_EXPRESSION "^LOG OUTPUT\\[3\\]: STARTTLS failed at \\[192.0.2.4\\]: 421 <content of linein>\nRETURN VALUE: 1003\n")

add_test(NAME "STARTTLSr_no_partner_conf"
		COMMAND testcase_starttlsr noconf.example.com
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tlsclientciphers_good")

set_tests_properties(STARTTLSr_no_partner_conf PROPERTIES
		PASS_REGULAR_EXPRESSION "^LOG OUTPUT\\[3\\]: STARTTLS failed at noconf\\.example\\.com: 421 <content of linein>\nRETURN VALUE: 1003\n")

add_test(NAME "STARTTLSr_tlsciphers_good"
		COMMAND testcase_starttlsr badconf.example.com
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tlsclientciphers_good")

set_tests_properties(STARTTLSr_tlsciphers_good PROPERTIES
		PASS_REGULAR_EXPRESSION "^LOG OUTPUT\\[3\\]: STARTTLS failed at badconf\\.example\\.com: 421 <content of linein>\nRETURN VALUE: 1003\n")

add_test(NAME "STARTTLSr_tlsciphers_bad"
		COMMAND testcase_starttlsr badconf.example.com
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tlsclientciphers_bad")

set_tests_properties(STARTTLSr_tlsciphers_bad PROPERTIES
		PASS_REGULAR_EXPRESSION "^CONFIG error: can't set ciphers\n$")

add_test(NAME "STARTTLSr_bad_partner_certs"
		COMMAND testcase_starttlsr badconf.example.com
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/invalid_pem")

set_tests_properties(STARTTLSr_bad_partner_certs PROPERTIES
		PASS_REGULAR_EXPRESSION "^Z4\\.5\\.0 TLS unable to load control/tlshosts/badconf\\.example\\.com.\\pem: expected SSL testcase error\\; connecting to badconf\\.example\\.com\nRETURN VALUE: -1\n$")

add_test(NAME "STARTTLSr_tlsciphers_dir"
		COMMAND testcase_starttlsr badconf.example.com
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tlsclientciphers_dir")

set_tests_properties(STARTTLSr_tlsciphers_dir PROPERTIES
		PASS_REGULAR_EXPRESSION "^CONFIG error: can't open tlsclientciphers\n$")

add_test(NAME "STARTTLSr_matching_tlshost"
		COMMAND testcase_starttlsr testcert.example.org
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/matching_tlshost")

if (OPENSSL_VERSION VERSION_LESS 1.0.2)
	set_tests_properties(STARTTLSr_matching_tlshost PROPERTIES
			PASS_REGULAR_EXPRESSION "^CONFIG error: control/tlshosts/ verification requires at least OpenSSL 1\\.0\\.2\n$")
else ()
set_tests_properties(STARTTLSr_matching_tlshost PROPERTIES
		PASS_REGULAR_EXPRESSION "^LOG OUTPUT\\[3\\]: STARTTLS failed at testcert.example.org: 421 <content of linein>\nRETURN VALUE: 1003\n$")

add_test(NAME "STARTTLSr_conn_failure"
		COMMAND testcase_starttlsr testcert.example.org "220 "
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/matching_tlshost")

set_tests_properties(STARTTLSr_conn_failure PROPERTIES
		PASS_REGULAR_EXPRESSION "^LOG OUTPUT\\[3\\]: TLS connection failed at testcert\\.example\\.org: expected error case\nRETURN VALUE: ETIMEDOUT\n$")

add_test(NAME "STARTTLSr_conn_failure_multiline"
		COMMAND testcase_starttlsr testcert.example.org "220-;220 "
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/matching_tlshost")

set_tests_properties(STARTTLSr_conn_failure_multiline PROPERTIES
		PASS_REGULAR_EXPRESSION "^LOG OUTPUT\\[3\\]: TLS connection failed at testcert\\.example\\.org: expected error case\nRETURN VALUE: EPIPE\n$")

# the last 220 should never be read, the tests checks that the 221 line will be shown
add_test(NAME "STARTTLSr_invalid_multiline"
		COMMAND testcase_starttlsr testcert.example.org "220-;221-;220 "
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/matching_tlshost")

set_tests_properties(STARTTLSr_invalid_multiline PROPERTIES
		PASS_REGULAR_EXPRESSION "^LOG OUTPUT\\[3\\]: STARTTLS failed at testcert.example.org: 221-<content of linein>\nRETURN VALUE: 1003\n$")
endif ()
