cmake_minimum_required(VERSION 3.12)
cmake_policy(SET CMP0074 OLD)

project(ARX)

##################################################
# Compiler flags
include(cmake/ucm.cmake)

ucm_set_runtime(STATIC)
ucm_add_flags(
	"/O2"
	"/Ob2"
	"/EHsc"
	"/std:c++17"
	"/Zc:threadSafeInit-"
	"/Zc:dllexportInlines-"
	"/guard:cf-"
)

ucm_add_linker_flags("/INCREMENTAL:NO" "/OPT:REF" "/OPT:ICF")
ucm_add_linker_flags("/SUBSYSTEM:CONSOLE,6.00")
add_compile_definitions("WINVER=0x0600" "_WIN32_WINNT=0x0600" "_CRT_SECURE_NO_WARNINGS")

##################################################
# Preprocessor definitions
add_compile_definitions(
	WIN32
	UNICODE
	_UNICODE
	NOMINMAX)

##################################################
# Conan integration
set(CONAN_DISABLE_CHECK_COMPILER TRUE)
include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()
message("CONAN_INCLUDE_DIRS=${CONAN_INCLUDE_DIRS}")
message("CMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}")
message("CMAKE_EXE_LINKER_FLAGS=${CMAKE_EXE_LINKER_FLAGS}")

##################################################
# Main taget
add_executable(arx
	src/main.cpp
	src/hexcodec.h)
target_include_directories(arx PUBLIC src)
target_link_libraries(arx ${CONAN_LIBS})

##################################################
# ARX.DLL
set(FASM_PATH "C:/FASM")
add_custom_command(
	TARGET arx POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E env "PATH=${FASM_PATH}" "INCLUDE=${FASM_PATH}/INCLUDE;${CMAKE_CURRENT_LIST_DIR}/src" fasm.exe ARX.ASM
	COMMAND ${CMAKE_COMMAND} -E copy_if_different ARX.DLL ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
	BYPRODUCTS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/ARX.DLL
	WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/src
)