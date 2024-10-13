cmake_minimum_required(VERSION 3.16)
project(example_project)

# Gather source and header files
file(GLOB_RECURSE sources src/*.cpp src/*.h src/assistance/* src/seccomp/* src/supervised_p/* src/supervisor/*)
file(GLOB_RECURSE data resources/*)

# Create the executable
add_executable(example ${sources} ${data})

# Set compiler options
target_compile_options(example PUBLIC -std=c++1y -Wall -Wfloat-conversion)

# Include directories for the target
target_include_directories(example PUBLIC src/main)

# Copy resource files to the build directory
file(COPY ${data} DESTINATION resources)

# Find and link Boost libraries
find_package(Boost 1.36.0 COMPONENTS filesystem system REQUIRED)
target_link_libraries(example PUBLIC ${Boost_LIBRARIES})

# Install targets and resources
install(TARGETS example DESTINATION example_destination)
install(DIRECTORY resources DESTINATION example_destination)

# Package settings
set(CPACK_PACKAGE_NAME "MyExample")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_MONOLITHIC_INSTALL 1)
include(CPack)