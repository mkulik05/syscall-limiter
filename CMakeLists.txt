cmake_minimum_required(VERSION 3.16)

project(PiVOX VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstandalone-debug")


set(SRC_FILES
    src/main.cpp
    src/seccomp/seccomp.cpp
    src/ProcessManager/ProcessManager.cpp
    src/SocketBridge/SocketBridge.cpp
    src/Supervisor/handlers/handlers.cpp
    src/Supervisor/Manager/Supervisor.cpp
    src/Logger/Logger.cpp
)

set(HEADER_FILES
    src/seccomp/seccomp.h
    src/ProcessManager/ProcessManager.h
    src/SocketBridge/SocketBridge.h
    src/Supervisor/Manager/Supervisor.h
    src/Supervisor/handlers/handlers.h
    src/rules/rules.h
    src/Logger/Logger.h
)


add_executable(result
    ${SRC_FILES}
    ${HEADER_FILES}
)

set_target_properties(result PROPERTIES
    WIN32_EXECUTABLE ON
    MACOSX_BUNDLE ON
)