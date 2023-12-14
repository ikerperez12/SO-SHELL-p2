cmake_minimum_required(VERSION 3.26)
project(untitled C)

set(CMAKE_C_STANDARD 17)

# Verificar si se está compilando en WSL
if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    # Configuración para Linux o WSL
    add_executable(untitled p2.c commands.c commands.h)
    # Agregar las bibliotecas de Linux necesarias
    target_link_libraries(untitled -lm)

    # Valgrind
    find_program(Valgrind valgrind)
    if (Valgrind)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g") # Opcional:  generar símbolos de depuración
        add_custom_target(valgrind
                COMMAND ${Valgrind} --tool=memcheck --leak-check=full --track-origins=yes ./untitled
                DEPENDS untitled
                WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                COMMENT "Running Valgrind..."
        )
    else()
        message(STATUS "Valgrind not found. Skipping Valgrind integration.")
    endif ()
else ()
    # Configuración para Windows nativo
    add_executable(untitled p2.c commands.c commands.h)
    # Agregar las bibliotecas de Linux necesarias también para Windows
    target_link_libraries(untitled -lm)
    # Agregar las bibliotecas específicas de Windows si es necesario
    target_link_libraries(untitled -lws2_32)
endif ()
