add_executable(testcase_vpop_user_exists
		userexists_test.c)

target_link_libraries(testcase_vpop_user_exists
		Qsmtpd_user_vpopm
		qsmtp_lib
		testcase_io_lib
		${MEMCHECK_LIBRARIES}
)

add_test(NAME "VPop_user_exists"
		COMMAND testcase_vpop_user_exists
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
