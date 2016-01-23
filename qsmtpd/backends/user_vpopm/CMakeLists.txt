project(Qs_user_vpopm C)

add_library(Qsmtpd_user_vpopm STATIC
	getfile.c
	vpop.c
	${CMAKE_SOURCE_DIR}/include/qsmtpd/vpop.h
)

target_link_libraries(Qsmtpd_user_vpopm
	qsmtp_lib
	${MEMCHECK_LIBRARIES}
)
