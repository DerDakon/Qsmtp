PROJECT(Qsmtp C)

SET(AUTOQMAIL /var/qmail)

ADD_DEFINITIONS(-Wall -W -Wshadow -Wno-sign-compare -Wno-pointer-sign -DNOSTDERR -DUSESYSLOG)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

ADD_SUBDIRECTORY(lib)
ADD_SUBDIRECTORY(qsmtpd)
ADD_SUBDIRECTORY(qremote)
ADD_SUBDIRECTORY(tools)

INSTALL(FILES doc/man/Qremote.8 doc/man/Qsmtpd.8 DESTINATION man/man8)
INSTALL(FILES doc/man/filterconf.5 DESTINATION man/man5)
