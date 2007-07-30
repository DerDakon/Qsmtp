SET_SOURCE_FILES_PROPERTIES(qremote.c PROPERTIES COMPILE_FLAGS -DAUTOQMAIL='"${AUTOQMAIL}"')
ADD_EXECUTABLE(Qremote
	qremote.c
	conn.c
	starttlsr.c
	qrdata.c
)
TARGET_LINK_LIBRARIES(Qremote
	qsmtp_lib
	ssl
	owfat
)

INSTALL(TARGETS Qremote DESTINATION bin COMPONENT core)

#install:
#	install -s -g qmail -o qmailr Qremote $(AUTOQMAIL)/bin
