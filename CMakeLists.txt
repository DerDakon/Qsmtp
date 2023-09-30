cmake_minimum_required(VERSION 3.0...3.27 FATAL_ERROR)

project(Qsmtp
	VERSION 0.39
	LANGUAGES C)
	# 3.12+ HOMEPAGE_URL "https://opensource.sf-tec.de/Qsmtp/"

option(CHECK_MEMORY "Add memory access checks" OFF)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED On)

include(AddCCompilerFlag)
include(CheckCCompilerFlag)
include(CheckCSourceCompiles)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(CMakeDependentOption)
include(CTest)
include(GNUInstallDirs)

# Find library needed for connect. Taken from FindX11.cmake
check_function_exists("connect" CMAKE_HAVE_CONNECT)
if(NOT CMAKE_HAVE_CONNECT)
	check_library_exists("socket" "connect" "" CMAKE_LIB_SOCKET_HAS_CONNECT)
	if (CMAKE_LIB_SOCKET_HAS_CONNECT)
		set(CMAKE_SOCKET_LIB socket)
	endif ()
endif()

find_package(owfat REQUIRED)

if (AUTOQMAIL)
	if (NOT IS_ABSOLUTE "${AUTOQMAIL}")
		message(SEND_ERROR "The value '${AUTOQMAIL}' given for the AUTOQMAIL variable does not name an absolute path")
	endif ()
else ()
	find_program(QMAIL_SHOWCTL NAME qmail-showctl HINTS /var/qmail/bin)
	if (QMAIL_SHOWCTL)
		execute_process(COMMAND ${QMAIL_SHOWCTL} OUTPUT_VARIABLE QMAIL_CONF)
		string(REGEX REPLACE "\n.*" "" QMAIL_CONF "${QMAIL_CONF}")
		string(REGEX REPLACE "^qmail home directory:[\t ]+(.+)\\.$" "\\1" AUTOQMAIL "${QMAIL_CONF}")
		message(STATUS "qmail home directory autodetected as: ${AUTOQMAIL}")
	endif ()

	if (NOT AUTOQMAIL)
		set(AUTOQMAIL /var/qmail)
		message(STATUS "qmail home directory set to default: ${AUTOQMAIL}")
	endif ()
endif ()
set(AUTOQMAIL "${AUTOQMAIL}" CACHE PATH "Directory of qmail installation (usually /var/qmail)")

set(QSMTP_VERSION "${Qsmtp_VERSION}dev")

find_package(OpenSSL 1.1 REQUIRED)

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

ADD_C_COMPILER_FLAG(-Wall -W)
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

CHECK_SYMBOL_EXISTS(O_PATH "fcntl.h" HAS_O_PATH)
if (NOT HAS_O_PATH)
	set(CMAKE_REQUIRED_FLAGS "-D_GNU_SOURCE")
	CHECK_SYMBOL_EXISTS(O_PATH "fcntl.h" HAS_O_PATH_IN_GNU)
	unset(CMAKE_REQUIRED_FLAGS)
endif ()

CHECK_SYMBOL_EXISTS(POLLRDHUP "poll.h" HAS_POLLRDHUP)
if (NOT HAS_POLLRDHUP)
	set(CMAKE_REQUIRED_FLAGS "-D_GNU_SOURCE")
	CHECK_SYMBOL_EXISTS(POLLRDHUP "poll.h" HAS_POLLRDHUP_IN_GNU)
	unset(CMAKE_REQUIRED_FLAGS)
endif ()

CHECK_SYMBOL_EXISTS(strcasestr "string.h" HAS_STRCASESTR)
if (NOT HAS_STRCASESTR)
	set(CMAKE_REQUIRED_FLAGS "-D_GNU_SOURCE")
	CHECK_SYMBOL_EXISTS(strcasestr "string.h" HAS_STRCASESTR_IN_GNU)
	unset(CMAKE_REQUIRED_FLAGS)
endif ()

if (HAS_O_PATH_IN_GNU OR HAS_POLLRDHUP_IN_GNU OR HAS_STRCASESTR_IN_GNU)
	add_definitions(-D_GNU_SOURCE)
endif ()

set(CMAKE_REQUIRED_INCLUDES string.h)
CHECK_FUNCTION_EXISTS(explicit_bzero HAS_EXP_BZERO)
if (NOT HAS_EXP_BZERO)
	CHECK_FUNCTION_EXISTS(memset_s HAS_MEMSET_S)
	if (HAS_MEMSET_S)
		add_definitions(-DHAS_MEMSET_S)
	else ()
		CHECK_FUNCTION_EXISTS(explicit_memset HAS_EXP_MEMSET)
		if (HAS_EXP_MEMSET)
			add_definitions(-DUSE_EXPLICIT_MEMSET)
		endif ()
	endif ()
endif ()
if (NOT HAS_EXP_BZERO AND NOT HAS_MEMSET_S AND NOT HAS_EXP_MEMSET)
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

CHECK_FUNCTION_EXISTS(pipe2 HAS_PIPE2)

check_c_source_compiles("#include <netinet/in.h>
static struct in6_addr a;
int test_ip6(const struct in6_addr *i) {
  return i->s6_addr32[3] != 0;
}
int main() {
  return test_ip6(&a);
}
" HAS_S6ADDR32)
if (NOT HAS_S6ADDR32)
	check_c_source_compiles("#include <netinet/in.h>
	static struct in6_addr a;
	int test_ip6(const struct in6_addr *i) {
	  return i->__u6_addr.__u6_addr32[3] != 0;
	}
	int main() {
	return test_ip6(&a);
	}
	" HAS_U6ADDR32)
	if (HAS_U6ADDR32)
		message(STATUS "adding compat defines for struct in6_addr access (__u6_addr)")
		add_definitions(-Ds6_addr32=__u6_addr.__u6_addr32 -Ds6_addr16=__u6_addr.__u6_addr16)
	else ()
		check_c_source_compiles("#include <netinet/in.h>
		static struct in6_addr a;
		int test_ip6(const struct in6_addr *i) {
		  return i->_S6_un._S6_u32[3] != 0;
		}
		int main() {
		  return test_ip6(&a);
		}
		" HAS_S6U32)
		if (HAS_S6U32)
			message(STATUS "adding compat defines for struct in6_addr access (_S6_un)")
			add_definitions(-Ds6_addr32=_S6_un._S6_u32 -Ds6_addr16=_S6_un._S6_u16)
		else ()
			message(SEND_ERROR "unsupported layout of struct in6_addr")
		endif ()
	endif ()
endif()

check_c_source_compiles("#include <time.h>
int test_gmt(const struct tm *tm) {
  return tm->tm_gmtoff;
}
int main() {
  struct tm t = { 0 };
  return test_gmt(&t);
}
" HAS_GMTOFF)

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

option(BUILD_DEVTOOLS "Build also tools only useful for development" OFF)

add_subdirectory(tools)

if (BUILD_TESTING)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/CTestCustom.cmake ${CMAKE_CURRENT_BINARY_DIR}/CTestCustom.cmake @ONLY)

	enable_testing()

	add_subdirectory(tests)
endif ()

option(BUILD_DOC "Build documentation" ON)
CMAKE_DEPENDENT_OPTION(BUILD_API_DOC "Build API documentation" OFF
			"BUILD_DOC" OFF)
if (BUILD_API_DOC)
	# API documentation
	find_package(Doxygen REQUIRED)

	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)

	add_custom_target(docu ALL
			COMMAND ${DOXYGEN_EXECUTABLE}
			WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html
		DESTINATION ${CMAKE_INSTALL_FULL_DOCDIR}
		COMPONENT development EXCLUDE_FROM_ALL)
endif ()

if (BUILD_DOC)
	# general documentation
	install(FILES
			${CMAKE_CURRENT_SOURCE_DIR}/doc/CREDITS
			${CMAKE_CURRENT_SOURCE_DIR}/doc/INSTALL
			${CMAKE_CURRENT_SOURCE_DIR}/doc/THOUGHTS
			${CMAKE_CURRENT_SOURCE_DIR}/doc/faq.html
			DESTINATION ${CMAKE_INSTALL_FULL_DOCDIR})

	# man pages
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/doc/man/Qremote.8 ${CMAKE_CURRENT_BINARY_DIR}/Qremote.8 @ONLY)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/doc/man/Qsmtpd.8 ${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd.8 @ONLY)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/doc/man/filterconf.5 ${CMAKE_CURRENT_BINARY_DIR}/filterconf.5 @ONLY)

	install(FILES
		${CMAKE_CURRENT_BINARY_DIR}/Qremote.8
		${CMAKE_CURRENT_BINARY_DIR}/Qsmtpd.8
		DESTINATION ${CMAKE_INSTALL_FULL_MANDIR}/man8)
	install(FILES
		${CMAKE_CURRENT_BINARY_DIR}/filterconf.5
		DESTINATION ${CMAKE_INSTALL_FULL_MANDIR}/man5)
endif ()
