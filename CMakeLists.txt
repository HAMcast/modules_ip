cmake_minimum_required(VERSION 2.6)
project (hamcast_libip_module)

if (CMAKE_BUILD_TYPE STREQUAL Debug)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -DHC_ENABLE_LOGGING -g -Wextra -Wall -pedantic")
else ()
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -O3")
endif (CMAKE_BUILD_TYPE STREQUAL Debug)
### uncomment if compiling for planetlab or other x86 systems
#set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=i486")

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
endif()

# Set up environment paths to cmake modules and libhamcast
set (CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})

#set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

find_package (Threads)
find_package (LibHamcast REQUIRED)

set (LIBIP_INCLUDE include/)
set (LIBIP_SRC  src/ip_socket.cpp 
                src/ip_instance.cpp 
                src/ip_module.cpp)

include_directories (${LIBIP_INCLUDE} ${HAMCAST_INCLUDE} )

add_library(libipmodule SHARED ${LIBIP_SRC})

target_link_libraries (libipmodule ${CMAKE_LD_LIBS}
                        ${CMAKE_THREAD_LIBS_INIT}
                        ${HAMCAST_LIBRARY}
                        ${OPENSSL_LIBRARIES})

# install lib
set (LIBIP_VERSION_MAJOR 0)
set (LIBIP_VERSION_MINOR 15)
set (LIBIP_VERSION_PATCH 1)
set (LIBRARY_VERSION ${LIBIP_VERSION_MAJOR}.${LIBIP_VERSION_MINOR}.${LIBIP_VERSION_PATCH})
set (LIBRARY_SOVERSION ${LIBIP_VERSION_MAJOR})
set_target_properties(libipmodule PROPERTIES 
                        SOVERSION ${LIBRARY_SOVERSION} 
                        VERSION ${LIBRARY_VERSION} 
                        OUTPUT_NAME ipmodule)
