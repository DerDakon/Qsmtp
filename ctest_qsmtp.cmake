##
## Qsmtp CTest script
##
## This will run a Nightly build on Qsmtp
##

##
## What you need:
##
## All platforms:
## -cmake >= 2.8.3
## -Subversion command line client
## -all the other stuff needed to build Qsmtp like openssl, compiler, ...
##

##
## How to setup:
##
## Write to a file my_qsmtp.cmake:
##
## ######### begin file
## # the binary directory does not need to exist (but it's parent)
## # it will be deleted before use
## set(QSMTP_BUILD_DIR "my/path/to/the/build/dir")
##
## # if you don't want to run a Nightly, but e.g. an Experimental build
## # set(dashboard_model "Experimental")
##
## # if your "git" executable can not be found by FindGit.cmake
## # set(GIT_EXECUTABLE "path/to/my/git")
##
## # if you only want to run the test, but not submit the results
## set(NO_SUBMIT TRUE)
##
## # if you are not on a openSUSE system the script currently doesn't
## # set a proper build name
## set(CTEST_BUILD_NAME "Fedora Core 14 x86_64")
##
## # add extra configure options
## # set(CONF_OPTIONS "-DIPV4ONLY=On")
##
## # This _*MUST*_ be the last command in this file!
## include(/path/to/Qsmtp/ctest_qsmtp.cmake)
## ######### end file
##
## Then run this script with
## ctest -S my_qsmtp_nightly.cmake -V
##

# Check for required variables.
foreach (req
                QSMTP_BUILD_DIR
        )
        if (NOT DEFINED ${req})
                message(FATAL_ERROR "The containing script must set ${req}")
        endif ()
endforeach ()

cmake_minimum_required(VERSION 2.8.6)

if (NOT GIT_EXECUTABLE)
	find_package(Git REQUIRED)
endif()
set(UpdateCommand ${GIT_EXECUTABLE})

set(CTEST_SOURCE_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})
set(CTEST_BINARY_DIRECTORY ${QSMTP_BUILD_DIR})

# Select the model (Nightly, Experimental, Continuous).
if (NOT DEFINED dashboard_model)
        set(dashboard_model Nightly)
endif()
if (NOT "${dashboard_model}" MATCHES "^(Nightly|Experimental|Continuous)$")
        message(FATAL_ERROR "dashboard_model must be Nightly, Experimental, or Continuous")
endif()

if (NOT CTEST_CMAKE_GENERATOR)
	set(CTEST_CMAKE_GENERATOR "Unix Makefiles")
endif ()

# set the site name
if (NOT CTEST_SITE)
	execute_process(COMMAND hostname --fqdn
			OUTPUT_VARIABLE CTEST_SITE
			OUTPUT_STRIP_TRAILING_WHITESPACE)
endif ()

# set the build name
if (NOT CTEST_BUILD_NAME)
	if (EXISTS /etc/SuSE-release)
		file(STRINGS /etc/SuSE-release _SUSEVERSION)
		list(GET _SUSEVERSION 0 _BUILDNAMETMP)
		string(REGEX REPLACE "[\\(\\)]" "" CTEST_BUILD_NAME ${_BUILDNAMETMP})
		unset(_SUSEVERSION)
	elseif (EXISTS /etc/os-release)
		file(STRINGS /etc/os-release _OSVERSION)
		foreach(_OSVERSION_STRING ${_OSVERSION})
			if (_OSVERSION_STRING MATCHES "^NAME=")
				string(REGEX REPLACE "^NAME=" "" _OSVER_NAME "${_OSVERSION_STRING}")
			elseif (_OSVERSION_STRING MATCHES "^VERSION_ID=")
				string(REGEX REPLACE "^VERSION_ID=\"(.*)\"" "\\1" _OSVER_VERSION "${_OSVERSION_STRING}")
			endif ()
		endforeach()
		unset(_OSVERSION)
		if (_OSVER_NAME AND _OSVER_VERSION)
			set(CTEST_BUILD_NAME "${_OSVER_NAME} ${_OSVER_VERSION}")
		endif ()
	endif ()
endif ()

if (NOT CTEST_BUILD_NAME)
	message(FATAL_ERROR "CTEST_BUILD_NAME not set.\nPlease set this to a sensible value, preferably in the form \"distribution version architecture\", something like \"openSUSE 11.3 i586\"")
endif ()

find_program(CTEST_MEMORYCHECK_COMMAND valgrind)
find_program(CTEST_COVERAGE_COMMAND gcov)

ctest_read_custom_files(${CMAKE_CURRENT_LIST_DIR})

ctest_empty_binary_directory(${CTEST_BINARY_DIRECTORY})

file(MAKE_DIRECTORY "${CTEST_BINARY_DIRECTORY}/var/qmail/control")
file(WRITE "${CTEST_BINARY_DIRECTORY}/var/qmail/control/me" "${CTEST_SITE}\n")

ctest_start(${dashboard_model})

ctest_update()

# avoid spamming the syslog with our messages: USESYSLOG off
list(APPEND CONF_OPTIONS "-DUSESYSLOG=Off" "-DNOSTDERR=On" "-DREALLY_NO_LOGGING=On")
# avoid spamming the dashboard with doxygen warnings: BUILD_DOC off
list(APPEND CONF_OPTIONS "-DBUILD_DOC=Off")
# get coverage: debug build
list(APPEND CONF_OPTIONS "-DCMAKE_BUILD_TYPE=Debug")
# let testcases find the prepared config files: set AUTOQMAIL
list(APPEND CONF_OPTIONS "-DAUTOQMAIL=${CTEST_BINARY_DIRECTORY}/var/qmail")
# get more coverage: enable some optional features
list(APPEND CONF_OPTIONS "-DCHUNKING=On" "-DAUTHCRAM=On")

ctest_configure(
		OPTIONS "${CONF_OPTIONS}"
)
ctest_build()

# The AUTH LOGIN wrong test will take 5 seconds where they are in a sleep,
# schedule more tests in parallel so this doesn't take too long.
ctest_test(PARALLEL_LEVEL 2)

if (CTEST_COVERAGE_COMMAND)
	ctest_coverage()
endif ()

if (CTEST_MEMORYCHECK_COMMAND)
	set(CTEST_MEMORYCHECK_SUPPRESSIONS_FILE "${CMAKE_CURRENT_LIST_DIR}/valgrind.supp")
	ctest_memcheck()
endif ()

if (NOT NO_SUBMIT)
	ctest_submit()
endif ()
