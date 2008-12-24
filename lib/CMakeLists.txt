INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

SET(QSMTP_LIB_SRCS
	netio.c
	dns.c
	log.c
	control.c
	ssl_timeoutio.c
	tls.c
	getfile.c
	base64.c
	match.c
	mime.c
	libowfatconn.c
	cdb.c
	xtext.c
	mmap.c
	fmt.c
)

SET(QSMTP_LIB_HDRS
	../include/base64.h
	../include/cdb.h
	../include/control.h
	../include/dns.h
	../include/fmt.h
	../include/log.h
	../include/match.h
	../include/mime.h
	../include/mmap.h
	../include/netio.h
	../include/ssl_timeoutio.h
	../include/sstring.h
	../include/tls.h
	${CMAKE_BINARY_DIR}/version.h
	../include/xtext.h
)

ADD_LIBRARY(qsmtp_lib ${QSMTP_LIB_SRCS} ${QSMTP_LIB_HDRS})
