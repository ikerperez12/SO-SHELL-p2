// commands.h
#ifndef COMMANDS_H
#define COMMANDS_H
#include <sys/stat.h>
#include <stddef.h>

#define MAX_COMMAND_SIZE 256
#define MAX_HISTORY_SIZE 4096
#define MAX_ARG_SIZE 64
#define MAX_BUFFER_SIZE 1024


typedef struct {
    int num_args;
    char args[MAX_ARG_SIZE][MAX_COMMAND_SIZE]; // Cambio en la declaración de args
    char command[MAX_COMMAND_SIZE];
} Command;


typedef struct {
    int long_format;   // Para las opciones -long o -l
    int access_time;   // Para la opción -acc
    int show_links;    // Para las opciones -link o -L
    int hidden_files;  // Para las opciones -hid o -h
    int recursive;     // Para las opciones -reca, -recb o -R
} ListOptions;


typedef struct MemoryBlock {
    void* address;
    size_t size;
    time_t allocation_time;
    enum { MALLOC, SHARED, MMAP } type;
    int key; // Para bloques de memoria compartida
    char filename[256]; // Para archivos mapeados
    int fd; // File descriptor para archivos mapeados
    struct MemoryBlock* next;
} MemoryBlock;

extern MemoryBlock* memory_blocks;


extern char input_buffer[MAX_BUFFER_SIZE];
extern char output_buffer[MAX_BUFFER_SIZE];


// Declaraciones de las funciones globales
extern void print_prompt();
extern void tokenize_input(char* input, Command* cmd);
extern void execute_command(Command* cmd);


extern Command history[MAX_HISTORY_SIZE];
extern int history_size;

void execute_command(Command* cmd);

void authors(Command* cmd);
void pid(Command* cmd);
void chdir_command(Command* cmd);
void date(void);
void time_command(void);
void hist(Command* cmd);
void comand(Command* cmd);
void open_command(Command* cmd);
void close_command(Command* cmd);
void dup_command(Command* cmd);
void listopen(void);
void infosys(void);
void help(Command* cmd);


void create_command(Command* cmd);
void stat_command(Command* cmd);
void list_command(Command* cmd);
void delete_command(Command* cmd);
void deltree_command(Command* cmd);


int esDireccionValida(void *addr, size_t count);

void dopmap(void);

void malloc_command(Command* cmd);
void shared_command(Command* cmd);
void mmap_command(Command* cmd);
void read_command(Command* cmd);
void write_command(Command* cmd);
void memdump_command(Command* cmd);
void memfill_command(Command* cmd);
void mem_command(Command* cmd);
void recurse_command(Command* cmd);

//auxiliar liberar memoria
void liberarBloqueMemoria(void* addr);


// Función de conversión de modo
char* ConvierteModo2(mode_t m);

#endif /* COMMANDS_H */
