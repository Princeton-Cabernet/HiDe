cmake_minimum_required(VERSION 3.17.0)
project(country_distances)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set O3 optimization explicitly
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

# Find GeographicLib
find_package(GeographicLib REQUIRED)
include_directories(${GeographicLib_INCLUDE_DIRS})

# Find OpenMP
find_package(OpenMP REQUIRED)
if(OpenMP_CXX_FOUND)
    message(STATUS "OpenMP found!")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif()

# Executables
add_executable(max_intracountry_distance max_intracountry_distance.cpp)
add_executable(min_intercountry_distance min_intercountry_distance.cpp)
add_executable(min_deviated_distance min_deviated_distance.cpp)
add_executable(min_post_distance_prefixes min_post_dist_prefixes.cpp)

# Link libraries
target_link_libraries(max_intracountry_distance
    ${GeographicLib_LIBRARIES}
    OpenMP::OpenMP_CXX
)
target_link_libraries(min_intercountry_distance
    ${GeographicLib_LIBRARIES}
    OpenMP::OpenMP_CXX
)
target_link_libraries(min_deviated_distance
    ${GeographicLib_LIBRARIES}
    OpenMP::OpenMP_CXX
)
target_link_libraries(min_post_distance_prefixes
    ${GeographicLib_LIBRARIES}
    OpenMP::OpenMP_CXX
)