cmake_minimum_required(VERSION 3.7...3.20)

macro(iptest testname pass_expr)
	add_test(NAME addipbl_${testname}
			COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/addipbl_test.sh "$<TARGET_FILE:addipbl>" "testout_${testname}" ${ARGN}
			WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
	set_tests_properties(addipbl_${testname} PROPERTIES PASS_REGULAR_EXPRESSION "${pass_expr}")
endmacro()

macro(dumpipbltest testname pass_expr)
	add_test(NAME dumpipbl_${testname}
			COMMAND dumpipbl -4 "${CMAKE_CURRENT_BINARY_DIR}/testout_${testname}")
	add_test(NAME addipbl_cleanup_${testname}
			COMMAND ${CMAKE_COMMAND} -E rm "${CMAKE_CURRENT_BINARY_DIR}/testout_${testname}")
	set_tests_properties(addipbl_cleanup_${testname} PROPERTIES FIXTURES_CLEANUP ipbl_${testname})
	set_tests_properties(addipbl_${testname} PROPERTIES FIXTURES_SETUP ipbl_${testname})
	set_tests_properties(dumpipbl_${testname} PROPERTIES
			DEPENDS addipbl_${testname}
			FIXTURES_REQUIRED ipbl_${testname})

	set_tests_properties(dumpipbl_${testname} PROPERTIES PASS_REGULAR_EXPRESSION "^${pass_expr}\n$")
endmacro()

iptest(localIP "00000 300 250 021 030 040" "192.168.17.24")
iptest(localNet "00000 300 250 021 030 036" "192.168.17.24/30")
iptest(2localIPs "00000 300 250 021 030 040 300 250 030 021 040" "192.168.17.24" "192.168.24.17")

iptest(mixed46 "error: IPv4 and IPv6 addresses cannot be mixed in the same file" "192.168.17.24/30" "::1")

iptest(invalid4_1 "invalid IP address in argument '192.268.17.24'" "192.268.17.24")
iptest(invalid4_2 "invalid IP address in argument '192,168.17.24/30'" "192,168.17.24/30")
iptest(invalid4_3 "invalid IP address in argument '192.168.17.2444'" "192.168.17.24" "192.168.17.2444")
iptest(invalid6_1 "invalid IP address in argument '::1::2'" "::1::2")
iptest(invalid6_2 "invalid IP address in argument '::1:j/48'" "::1:j/48")
iptest(invalid6_3 "invalid IP address in argument '::1:t'" "::2" "::1:t")
iptest(invalid4m_1 "invalid mask found in argument '192.168.17.24', ignoring" "192.168.17.24/t")
iptest(invalid4m_2 "mask not in valid range in argument '192.168.17.24', ignoring" "192.168.17.24/33")
iptest(invalid6m_1 "mask not in valid range in argument '::1', ignoring" "::1/4")

dumpipbltest(localIP "192\\\\.168\\\\.17\\\\.24/32")
dumpipbltest(localNet "192\\\\.168\\\\.17\\\\.24/30")
dumpipbltest(2localIPs "192\\\\.168\\\\.17\\\\.24/32\n192\\\\.168\\\\.24\\\\.17/32")
