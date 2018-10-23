project(Qsmtp C)

cmake_minimum_required(VERSION 2.8.6 FATAL_ERROR)

option(CHECK_MEMORY "Add memory access checks" OFF)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED On)

include(AddCCompilerFlag)
include(CheckCCompilerFlag)
include(CheckSymbolExists)
include(CheckFunctionExists)

find_package(owfat REQUIRED)

if (COMMAND cmake_policy)
	cmake_policy(SET CMP0003 NEW)
endif ()

if (AUTOQMAIL)
	if (NOT IS_ABSOLUTE "${AUTOQMAIL}")
		message(SEND_ERROR "The value '${AUTOQMAIL}' given for the AUTOQMAIL variable does not name an absolute path")
	endif ()
else ()
	set(AUTOQMAIL /var/qmail)
endif ()
set(AUTOQMAIL "${AUTOQMAIL}" CACHE PATH "Directory of qmail installation (usually /var/qmail)")

set(QSMTP_VERSION_MAJOR 0)
set(QSMTP_VERSION_MINOR 35)
set(QSMTP_VERSION_EXTRAVERSION dev)
set(QSMTP_VERSION "${QSMTP_VERSION_MAJOR}.${QSMTP_VERSION_MINOR}${QSMTP_VERSION_EXTRAVERSION}")

find_package(OpenSSL 1.0.2 REQUIRED)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/version.h.tmpl ${CMAKE_BINARY_DIR}/version.h @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/qmaildir.h.tmpl ${CMAKE_BINARY_DIR}/qmaildir.h @ONLY)

ADD_SUPPORTED_C_COMPILER_FLAG(CFLAGS_NO_SIGN_COMPARE -Wno-sign-compare)
ADD_SUPPORTED_C_COMPILER_FLAG(CFLAGS_NO_POINTER_SIGN -Wno-pointer-sign)
ADD_SUPPORTED_C_COMPILER_FLAG(CFLAGS_SHADOW -Wshadow)

if (CHECK_MEMORY)
	ADD_SUPPORTED_C_COMPILER_FLAG(CFLAGS_STACK_PROTECTOR -fstack-protector-all)
	
	CHECK_C_COMPILER_FLAG(-fmudflap CFLAGS_MUDFLAP)

	if (CFLAGS_MUDFLAP)
		find_package(mudflap)
		if (MUDFLAP_FOUND)
			ADD_C_COMPILER_FLAG(-fmudflap)
		endif ()
	endif ()

	find_package(ElectricFence)
	if (EFENCE_FOUND)
		set(MEMCHECK_LIBRARIES ${EFENCE_LIBRARIES})
	endif ()
endif ()

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -fprofile-arcs -ftest-coverage")

ADD_C_COMPILER_FLAG(-Wall -W -Wshadow)
add_definitions(-D_FILE_OFFSET_BITS=64)

# these warnings also warn about entirely empty (i.e. 0) structs
if (CMAKE_COMPILER_IS_GNUCC AND CMAKE_C_COMPILER_VERSION VERSION_LESS 5)
	ADD_SUPPORTED_C_COMPILER_FLAG(CFLAGS_NO_STRUCT_INIT -Wno-missing-field-initializers)
endif ()

CHECK_SYMBOL_EXISTS(O_CLOEXEC "fcntl.h" HAS_O_CLOEXEC)
if (NOT HAS_O_CLOEXEC)
	add_definitions(-DO_CLOEXEC=0)
endif ()

CHECK_SYMBOL_EXISTS(O_DIRECTORY "fcntl.h" HAS_O_DIRECTORY)
if (NOT HAS_O_DIRECTORY)
	add_definitions(-DO_DIRECTORY=0)
endif ()

set(CMAKE_REQUIRED_INCLUDES string.h)
CHECK_FUNCTION_EXISTS(explicit_bzero HAS_EXP_BZERO)
if (NOT HAS_EXP_BZERO)
	set(CMAKE_REQUIRED_INCLUDES bsd/string.h)
	find_library(LIBBSD NAMES bsd)
	if (LIBBSD)
		set(CMAKE_REQUIRED_LIBRARIES ${LIBBSD})
		CHECK_FUNCTION_EXISTS(explicit_bzero HAS_BSD_EXP_BZERO)
	endif ()
	option(ALLOW_INSECURE_BZERO "allow fallback to memset() when explicit_bzero() is not available" OFF)
	if (HAS_BSD_EXP_BZERO)
		add_definitions(-DNEED_BSD_STRING_H)
	elseif (NOT ALLOW_INSECURE_BZERO)
		message(SEND_ERROR "explicit_bzero() was not found, installing libbsd could help")
	else ()
		add_definitions(-DINSECURE_BZERO)
	endif ()
endif ()
set(CMAKE_REQUIRED_INCLUDES fcntl.h)
CHECK_FUNCTION_EXISTS(openat HAS_OPENAT)
unset(CMAKE_REQUIRED_INCLUDES)
if (NOT HAS_OPENAT)
	message(SEND_ERROR "Support for openat() is missing")
endif ()

option(NOSTDERR "Do not print error messages to stderr" ON)

option(USESYSLOG "Use syslog() for logging" ON)
if(USESYSLOG)
	add_definitions(-DUSESYSLOG)
endif()

option(IPV4ONLY "Disable support for IPv6 connections" OFF)
if(IPV4ONLY)
	add_definitions(-DIPV4ONLY)
endif()

option(CHUNKING "Enable CHUNKING extension (RfC 3030)" OFF)
if(CHUNKING)
	add_definitions(-DCHUNKING)
	if (NOT INCOMING_CHUNK_SIZE)
		set(INCOMING_CHUNK_SIZE 32)
	elseif (NOT INCOMING_CHUNK_SIZE MATCHES "^[1-9][0-9]*")
		message(SEND_ERROR "INCOMING_CHUNK_SIZE is no number: ${INCOMING_CHUNK_SIZE}")
	endif ()
	set(INCOMING_CHUNK_SIZE ${INCOMING_CHUNK_SIZE} CACHE STRING "size of buffer for incoming BDAT messages in kiB")
endif()

option(DEBUG_IO "Log the SMTP session" OFF)
if(DEBUG_IO)
	add_definitions(-DDEBUG_IO)
endif()

option(AUTHCRAM "Support CRAMMD5 authentication method" OFF)
if(AUTHCRAM)
	add_definitions(-DAUTHCRAM)
endif()

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/include
	${OPENSSL_INCLUDE_DIR}
	${CMAKE_BINARY_DIR}
)

add_subdirectory(lib)
add_subdirectory(qsmtpd)
add_subdirectory(qremote)
add_subdirectory(tools)

option(BUILD_TESTS "Build testcases" ON)
if (BUILD_TESTS)
	include(CTest)

	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/CTestCustom.cmake ${CMAKE_CURRENT_BINARY_DIR}/CTestCustom.cmake @ONLY)

	enable_testing()

	add_subdirectory(tests)
endif ()

option(BUILD_DOC "Build documentation" ON)
if (BUILD_DOC)
	# API documentation
	find_package(Doxygen REQUIRED)

	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)

	add_custom_target(docu ALL
			COMMAND ${DOXYGEN_EXECUTABLE}
			WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

	if (NOT DOC_DESTINATION_DIRECTORY)
		set(DOC_DESTINATION_DIRECTORY "doc/")
	endif ()

	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html DESTINATION ${DOC_DESTINATION_DIRECTORY})

	# general documentation
	install(FILES
			${CMAKE_CURRENT_SOURCE_DIR}/doc/CREDITS
			${CMAKE_CURRENT_SOURCE_DIR}/doc/INSTALL
			${CMAKE_CURRENT_SOURCE_DIR}/doc/THOUGHTS
			${CMAKE_CURRENT_SOURCE_DIR}/doc/faq.html
			DESTINATION ${DOC_DESTINATION_DIRECTORY})

	# man pages
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/doc/man/Qremote.8 ${CMAKE_CURRENT_BINARY_DIR}/Qremote.8 @ONLY)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/doc/man/Qsmtpd.8 ${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd.8 @ONLY)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/doc/man/filterconf.5 ${CMAKE_CURRENT_BINARY_DIR}/filterconf.5 @ONLY)

	install(FILES
		${CMAKE_CURRENT_BINARY_DIR}/Qremote.8
		${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd.8
		DESTINATION man/man8)
	install(FILES
		${CMAKE_CURRENT_BINARY_DIR}/filterconf.5
		DESTINATION man/man5)
endif ()
