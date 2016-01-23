include(FindPackageHandleStandardArgs)

find_library(EFENCE_LIBRARY
		NAMES efence
)
mark_as_advanced(EFENCE_LIBRARY)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(efence DEFAULT_MSG EFENCE_LIBRARY)

if(EFENCE_FOUND)
	set(EFENCE_LIBRARIES ${EFENCE_LIBRARY})
endif()
