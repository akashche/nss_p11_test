
cmake_minimum_required ( VERSION 2.8.12 )
project ( nss_p11_test CXX )

add_executable ( ${PROJECT_NAME} test.cpp )

target_compile_options ( ${PROJECT_NAME} PRIVATE 
    -g
    -O0 )

target_include_directories ( ${PROJECT_NAME} PRIVATE
    /usr/include/nspr4 
    /usr/include/nss3 )

target_link_libraries ( ${PROJECT_NAME} PRIVATE
    nss3
    softokn3 )
