# minimum CMake version required
cmake_minimum_required(VERSION 3.15)
# Project name, version and description
project(website VERSION 1.0 DESCRIPTION "A simple website")

#option(DPP_BUILD_TEST OFF)
#option(BUILD_SHARED_LIBS OFF)

if(UNIX AND NOT APPLE) # linux
	set(CMAKE_THREAD_LIBS_INIT "-lpthread")
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
	set(CMAKE_HAVE_THREADS_LIBRARY 1)
	set(CMAKE_USE_WIN32_THREADS_INIT 0)
	set(CMAKE_USE_PTHREADS_INIT 1)
	set(THREADS_PREFER_PTHREAD_FLAG ON)
	set(HAVE_CXX_ATOMICS64_WITHOUT_LIB True)
	set(HAVE_CXX_ATOMICS_WITHOUT_LIB True)
endif()

# Add DPP as dependency
add_subdirectory(deps/cpp-httplib)
add_subdirectory(deps/json)

# Create an executable
#add_executable(${PROJECT_NAME}
#    src/main.cpp
    # your others files...
#)

add_executable(${PROJECT_NAME} 
	"src/main.cpp"
	"src/tools.cpp"
)
#file(GLOB ${PROJECT_NAME} CONFIGURE_DEPENDS "*.h" "*.cpp")

# Linking libraries
#target_link_libraries(${PROJECT_NAME}
#    cpp-httplib
#    #spdlog # if you need a logger. Don't forget to clone sources
#           # in the `deps/` directory
#)

# Specify includes
target_include_directories(${PROJECT_NAME} PRIVATE
   deps/cpp-httplib
   deps/json/include
   include
)

# Set C++ version
set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 17 # or 20 if you want something more recent
    CXX_STANDARD_REQUIRED ON
 )