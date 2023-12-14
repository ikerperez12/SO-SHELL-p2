// p1.h
#ifndef P1_H
#define P1_H

#include "commands.h"

#define MAX_BUFFER_SIZE 1024  // Define aquí el tamaño del buffer

// Declaraciones de funciones de p1.c
void print_prompt();
void tokenize_input(char* input, Command* cmd);
void execute_command(Command* cmd);

// Declaraciones de variables globales
extern char input_buffer[MAX_BUFFER_SIZE];
extern char output_buffer[MAX_BUFFER_SIZE];

#endif /* P1_H */
