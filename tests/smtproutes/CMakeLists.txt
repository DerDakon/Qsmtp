set(ROUTES_TESTS nomatch complete_match with_port port_0 port_100k port_char port_char_no_relay
		no_colon port_only unresolved
		cert_dir cert_split cert_split_default cert_missing_dir cert_missing_key
		complete_match_dir with_port_dir port_0_dir port_100k_dir port_char_dir port_only_dir
		port_char_no_relay_dir unresolved_dir duplicate_host_dir invalid_entry_dir
		invalid_oip_dir invalid_oip6_dir ip4_as_oip6_dir
		no_equal_dir start_equal_dir)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/..")

add_executable(testcase_smtproutes
		smtproutes_test.c
		${CMAKE_SOURCE_DIR}/qremote/smtproutes.c)
target_link_libraries(testcase_smtproutes
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
		${CMAKE_SOCKET_LIB}
)

foreach (ROUTETEST IN LISTS ROUTES_TESTS)
	add_test(NAME "SMTProutes-${ROUTETEST}"
			COMMAND testcase_smtproutes
			WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/${ROUTETEST}")
	if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${ROUTETEST}/errmsg")
		file(READ "${CMAKE_CURRENT_SOURCE_DIR}/${ROUTETEST}/errmsg" ROUTETEST_MSG)
		set_tests_properties(SMTProutes-${ROUTETEST} PROPERTIES
			PASS_REGULAR_EXPRESSION "^(.*\n)?LOG: ${ROUTETEST_MSG}(\n.*)?$")
	else ()
		set_tests_properties(SMTProutes-${ROUTETEST} PROPERTIES
			FAIL_REGULAR_EXPRESSION "^(.*\n)?LOG: ")
	endif ()
endforeach ()
