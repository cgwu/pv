project(PV)

# set headers and sources
set (${PROJECT_NAME}_headers "")
set (${PROJECT_NAME}_sources main.cpp)

# create binaries
add_executable (${PROJECT_NAME} ${${PROJECT_NAME}_headers} ${${PROJECT_NAME}_sources})

# link
#target_link_libraries(${PROJECT_NAME} dll1)

# config install
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib/static)

