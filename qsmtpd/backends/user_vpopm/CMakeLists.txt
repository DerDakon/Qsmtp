PROJECT(Qs_user_vpopm C)

ADD_LIBRARY(Qsmtpd_user_vpopm STATIC
	getfile.c
	vpop.c
	${CMAKE_SOURCE_DIR}/include/qsmtpd/vpop.h
)

TARGET_LINK_LIBRARIES(Qsmtpd_user_vpopm
	qsmtp_lib
	${MEMCHECK_LIBRARIES}
)
