include(FindPackageHandleStandardArgs)

find_path(OWFAT_INCLUDE_DIR
		PATH_SUFFIXES libowfat
		PATHS /opt/diet/include
		NAMES taia.h
)
mark_as_advanced(OWFAT_INCLUDE_DIR)

find_library(OWFAT_LIBRARY
		NAMES owfat
		PATHS /opt/diet/lib
)
mark_as_advanced(OWFAT_LIBRARY)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(owfat DEFAULT_MSG OWFAT_LIBRARY OWFAT_INCLUDE_DIR)

if(OWFAT_FOUND)
	if (NOT TARGET owfat::owfat)
		add_library(owfat::owfat STATIC IMPORTED)
		set_target_properties(owfat::owfat PROPERTIES
			INTERFACE_INCLUDE_DIRECTORIES "${OWFAT_INCLUDE_DIR}")

		set_target_properties(owfat::owfat PROPERTIES
			IMPORTED_LINK_INTERFACE_LANGUAGES "C"
			IMPORTED_LOCATION "${OWFAT_LIBRARY}")
	endif ()
	set(OWFAT_INCLUDE_DIRS ${OWFAT_INCLUDE_DIR})
endif()
