find_package(Backtrace)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/qs_backtrace.h.in ${CMAKE_CURRENT_BINARY_DIR}/qs_backtrace.h @ONLY)

include_directories(
		${Backtrace_INCLUDE_DIRS}
		${CMAKE_CURRENT_BINARY_DIR}
)

add_library(testcase_io_lib STATIC
	testcase_io.h
	testcase_io_p.h
	test_io.c
	test_io_log.c
	test_io_net.c
	test_io_qdns.c
	test_io_tls.c
)

target_link_libraries(testcase_io_lib ${Backtrace_LIBRARIES})
