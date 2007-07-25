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

ADD_LIBRARY(qsmtp_lib ${QSMTP_LIB_SRCS})
