#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "AWS::aws-lambda-runtime" for configuration "Release"
set_property(TARGET AWS::aws-lambda-runtime APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(AWS::aws-lambda-runtime PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libaws-lambda-runtime.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS AWS::aws-lambda-runtime )
list(APPEND _IMPORT_CHECK_FILES_FOR_AWS::aws-lambda-runtime "${_IMPORT_PREFIX}/lib/libaws-lambda-runtime.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
