macro(iptest testname pass_expr)
	add_test(NAME addipbl_${testname}
			COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/addipbl_test.sh "$<TARGET_FILE:addipbl>" "testout_${testname}" ${ARGN}
			WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
	set_tests_properties(addipbl_${testname} PROPERTIES PASS_REGULAR_EXPRESSION "${pass_expr}")
endmacro()

iptest(localIP "a8c0[ \t]*1811[ \t]*0020" "192.168.17.24")
iptest(localNet "a8c0[ \t]*1811[ \t]*001e" "192.168.17.24/30")
iptest(2localIPs "a8c0[ \t]*1811[ \t]*c020[ \t]*18a8[ \t]*2011" "192.168.17.24" "192.168.24.17")

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
