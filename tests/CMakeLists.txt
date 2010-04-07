ADD_EXECUTABLE(testcase_spf
		spf_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/spf.c
		${CMAKE_SOURCE_DIR}/lib/dns_helpers.c
		${CMAKE_SOURCE_DIR}/lib/fmt.c
		${CMAKE_SOURCE_DIR}/lib/match.c
)

ADD_TEST(NAME "SPF_redhat" COMMAND testcase_spf "redhat")
ADD_TEST(NAME "SPF_sf-mail" COMMAND testcase_spf "sf-mail")

ADD_EXECUTABLE(testcase_control
		control_test.c
		${CMAKE_SOURCE_DIR}/lib/control.c
		${CMAKE_SOURCE_DIR}/lib/log.c
		${CMAKE_SOURCE_DIR}/lib/mmap.c)

ADD_TEST(NAME "Control" COMMAND testcase_control)
