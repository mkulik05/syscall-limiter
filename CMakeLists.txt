cmake_minimum_required(VERSION 3.16)

project(PiVOX VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstandalone-debug")


set(SRC_FILES
    src/main.cpp
    src/logic/seccomp/seccomp.cpp
    src/logic/ProcessManager/ProcessManager.cpp
    src/logic/SocketBridge/SocketBridge.cpp
    src/logic/Supervisor/handlers/handlers.cpp
    src/logic/Supervisor/Manager/Supervisor.cpp
    src/logic/Logger/Logger.cpp
)

set(HEADER_FILES
    src/logic/seccomp/seccomp.h
    src/logic/ProcessManager/ProcessManager.h
    src/logic/SocketBridge/SocketBridge.h
    src/logic/Supervisor/Manager/Supervisor.h
    src/logic/Supervisor/handlers/handlers.h
    src/logic/rules/rules.h
    src/logic/Logger/Logger.h
)


add_executable(result
    ${SRC_FILES}
    ${HEADER_FILES}
)

set_target_properties(result PROPERTIES
    WIN32_EXECUTABLE ON
    MACOSX_BUNDLE ON
)