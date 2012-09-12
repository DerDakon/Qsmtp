INCLUDE_DIRECTORIES(
		${CMAKE_SOURCE_DIR}/include
		${OWFAT_INCLUDE_DIRS}
)

SET(QSMTP_IO_LIB_SRCS
	libowfatconn.c
	log.c
	netio.c
	qdns.c
	ssl_timeoutio.c
	tls.c
)

SET(QSMTP_IO_LIB_HDRS
	../include/log.h
	../include/netio.h
	../include/qdns.h
	../include/ssl_timeoutio.h
	../include/tls.h
)

ADD_LIBRARY(qsmtp_io_lib ${QSMTP_IO_LIB_SRCS} ${QSMTP_IO_LIB_HDRS})
TARGET_LINK_LIBRARIES(qsmtp_io_lib
		${OPENSSL_LIBRARIES}
		${OWFAT_LIBRARIES}
)

SET(QSMTP_LIB_SRCS
	dns_helpers.c
	control.c
	getfile.c
	base64.c
	ipme.c
	match.c
	mime.c
	cdb.c
	xtext.c
	mmap.c
	fmt.c
	addrsyntax.c
)

SET(QSMTP_LIB_HDRS
	../include/base64.h
	../include/cdb.h
	../include/control.h
	../include/fmt.h
	../include/ipme.h
	../include/match.h
	../include/mime.h
	../include/mmap.h
	../include/sstring.h
	${CMAKE_BINARY_DIR}/version.h
	../include/xtext.h
)

ADD_LIBRARY(qsmtp_lib ${QSMTP_LIB_SRCS} ${QSMTP_LIB_HDRS})

# qsmtp_lib is not linked against qsmtp_io_lib even if that
# would be the right thing for the binaries. This allows the
# testcases to easily link against qsmtp_lib and implementing
# the io stuff themself.
