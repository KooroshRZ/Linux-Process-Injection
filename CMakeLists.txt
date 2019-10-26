cmake_minimum_required(VERSION 3.14)
project(ProcessInjectorLinux)

set(CMAKE_CXX_STANDARD 14)

add_executable(ProcessInjectorLinux Injection.cpp Injection.h Payload.cpp)


target_link_libraries(ProcessInjectorLinux ${CMAKE_DL_LIBS})