SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -fprofile-arcs -ftest-coverage")

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
		${CMAKE_SOURCE_DIR}/lib/mmap.c)

ADD_TEST(NAME "Control" COMMAND testcase_control)

ADD_EXECUTABLE(testcase_base64
		base64_test.c
		${CMAKE_SOURCE_DIR}/lib/base64.c)

ADD_TEST(NAME "Base64" COMMAND testcase_base64)

ADD_EXECUTABLE(testcase_cdb
		cdb_test.c
		${CMAKE_SOURCE_DIR}/qsmtpd/vpop.c)
TARGET_LINK_LIBRARIES(testcase_cdb qsmtp_lib)

ADD_TEST(NAME "CDB" COMMAND testcase_cdb "${CMAKE_CURRENT_SOURCE_DIR}/cdb-demo")

# 
# SET_TARGET_PROPERTIES(testcase_spf
# 		testcase_control
# 		testcase_base64
# 		PROPERTIES
# 		LINK_FLAGS_DEBUG "-fprofile-arcs -ftest-coverage"
# )
