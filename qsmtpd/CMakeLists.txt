add_subdirectory(filters)
add_subdirectory(backends)

set(QSMTPD_SRCS
	addrparse.c
	addrsyntax.c
	antispam.c
	auth.c
	child.c
	commands.c
	queue.c
	qsmtpd.c
	starttls.c
	spf.c
	data.c
	syntax.c
	xtext.c
)

if (CHUNKING)
	set_property(SOURCE data.c APPEND PROPERTY COMPILE_DEFINITIONS INCOMING_CHUNK_SIZE=${INCOMING_CHUNK_SIZE})
endif ()

set(QSMTPD_HDRS
	../include/qsmtpd/addrparse.h
	../include/qsmtpd/antispam.h
	../include/qsmtpd/commands.h
	../include/qsmtpd/queue.h
	../include/qsmtpd/qsauth.h
	../include/qsmtpd/qsauth_backend.h
	../include/qsmtpd/qsdata.h
	../include/qsmtpd/qsmtpd.h
	../include/qsmtpd/syntax.h
	../include/qsmtpd/userfilters.h
)

add_executable(Qsmtpd
	${QSMTPD_SRCS}
	${QSMTPD_HDRS}
)

target_link_libraries(Qsmtpd
	qsmtp_lib
	qsmtp_io_lib
	rcptfilters
	Qsmtpd_auth_checkpassword
	Qsmtpd_user_vpopm
	${MEMCHECK_LIBRARIES}
)

if (HAS_BSD_EXP_BZERO)
	target_link_libraries(Qsmtpd
		${LIBBSD}
	)
endif()

install(TARGETS Qsmtpd DESTINATION bin COMPONENT core)

#install:
#	install -s -g qmail -o qmaild Qsmtpd $(AUTOQMAIL)/bin
