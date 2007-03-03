SET_SOURCE_FILES_PROPERTIES(qremote.c PROPERTIES COMPILE_FLAGS -DAUTOQMAIL='${AUTOQMAIL}')
#SET_SOURCE_FILES_PROPERTIES(qremote.c PROPERTIES OBJECT_DEPENDS netio.h dns.h control.h log.h sstring.h conn.h starttlsr.h qrdata.h
#						COMPILE_FLAGS -DAUTOQMAIL='${AUTOQMAIL}')
#SET_SOURCE_FILES_PROPERTIES(conn.c PROPERTIES OBJECT_DEPENDS conn.h dns.h control.h log.h match.h)
#SET_SOURCE_FILES_PROPERTIES(starttlsr.c PROPERTIES OBJECT_DEPENDS tls.h ssl_timeoutio.h qremote.h control.h netio.h sstring.h starttlsr.h)
#SET_SOURCE_FILES_PROPERTIES(qrdata.c PROPERTIES OBJECT_DEPENDS netio.h qrdata.h qremote.h version.h mime.h log.h qoff.h)
#SET_SOURCE_FILES_PROPERTIES(qrauth.c PROPERTIES OBJECT_DEPENDS qremote.h netio.h log.h)
