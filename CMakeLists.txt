CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

# PE Viewer
# ------------------
project(PEViewer_SLN)
SET(VERSION_MAJOR "1")
SET(VERSION_MINOR "0")
SET(VERSION_PATCH "0")
SET(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}/bin)

# set env
# ------------------
#add_definitions(-DDEF_RET_YES)
#include_directories(${PROJECT_SOURCE_DIR}/inc)
#link_directories(${PROJECT_SOURCE_DIR}/external/lib)

message("Binary tree path: ${PROJECT_BINARY_DIR}")

# add subfolders
# -------------------

add_subdirectory(main)

