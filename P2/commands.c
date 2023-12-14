// commands.c
#include "commands.h"
#include <sys/stat.h>
#include <stdio.h>
#ifdef __linux__
#include <sys/utsname.h>
#endif

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "p2.h"
#include <time.h>
#include <dirent.h>
#include <errno.h>
#include "commands.h"
#include <sys/stat.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/mman.h>


#define MAX_COMMAND_SIZE 256
#define MAX_HISTORY_SIZE 4096
#define MAX_ARG_SIZE 64
#define MAX_RECURSION_DEPTH 100



// Estructura para gestionar los archivos abiertos
typedef struct {
    int fd;
    char filename[MAX_COMMAND_SIZE];
    char mode[MAX_COMMAND_SIZE];
} OpenFile;

OpenFile open_files[MAX_HISTORY_SIZE]; // Almacenar archivos abiertos
int open_files_count = 0;

Command history[MAX_HISTORY_SIZE];
int history_size = 0;

MemoryBlock* memory_blocks = NULL;


char* ConvierteModo2(mode_t m) {
    static char permisos[12];
    strcpy(permisos, "---------- ");

    if (S_ISDIR(m)) permisos[0] = 'd';
    if (m & S_IRUSR) permisos[1] = 'r';
    if (m & S_IWUSR) permisos[2] = 'w';
    if (m & S_IXUSR) permisos[3] = 'x';
    if (m & S_IRGRP) permisos[4] = 'r';
    if (m & S_IWGRP) permisos[5] = 'w';
    if (m & S_IXGRP) permisos[6] = 'x';
    if (m & S_IROTH) permisos[7] = 'r';
    if (m & S_IWOTH) permisos[8] = 'w';
    if (m & S_IXOTH) permisos[9] = 'x';

    return permisos;
}

void authors(Command* cmd) {
    if (cmd->num_args == 0) {
        printf("Authors: Iker Jesús Perez García, Diego Losada Gómez\n");
    } else if (cmd->num_args == 1 && strcmp(cmd->args[0], "-l") == 0) {
        printf("Logins: iker.perez@udc.es , diego.lgomez@udc.es \n");
    } else if (cmd->num_args == 1 && strcmp(cmd->args[0], "-n") == 0) {
        printf("Names: Iker Perez, Diego Losada \n");
    } else {
        printf("Invalid usage of authors command.\n");
    }
}

void pid(Command* cmd) {
    if (cmd->num_args == 0) {
        printf("PID of the shell: %d\n", getpid());
    } else if (cmd->num_args == 1 && strcmp(cmd->args[0], "-p") == 0) {
        printf("Parent PID of the shell: %d\n", getpid());
    } else {
        printf("Invalid usage of pid command.\n");
    }
}

void chdir_command(Command* cmd) {
    if (cmd->num_args == 0) {
        char cwd[1024];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            printf("Current directory: %s\n", cwd);
        } else {
            perror("getcwd");
        }
    } else if (cmd->num_args == 1) {
        if (chdir(cmd->args[0]) == 0) {
            printf("Changed directory to: %s\n", cmd->args[0]);
        } else {
            perror("chdir");
        }
    } else {
        printf("Invalid usage of chdir command.\n");
    }
}

void date(void) {
    time_t t;
    struct tm* info;
    time(&t);
    info = localtime(&t);
    printf("Current date: %02d/%02d/%04d\n", info->tm_mday, info->tm_mon + 1, info->tm_year + 1900);
}

void time_command(void) {
    time_t t;
    struct tm* info;
    time(&t);
    info = localtime(&t);
    printf("Current time: %02d:%02d:%02d\n", info->tm_hour, info->tm_min, info->tm_sec);
}

void hist(Command* cmd) {
    if (cmd->num_args == 0) {
        // List all commands in history
        for (int i = 0; i < history_size; i++) {
            printf("%d: %s", i, history[i].command);
            for (int j = 0; j < history[i].num_args; j++) {
                printf(" %s", history[i].args[j]);
            }
            printf("\n");
        }
    } else if (cmd->num_args == 1 && strcmp(cmd->args[0], "-c") == 0) {
        // Clear the history
        history_size = 0;
        printf("Command history cleared.\n");
    } else if (cmd->num_args == 2 && strcmp(cmd->args[0], "-N") == 0) {
        // List the first N commands in history
        int n = atoi(cmd->args[1]);
        if (n <= 0 || n > history_size) {
            printf("Invalid argument for hist -N.\n");
            return;
        }
        for (int i = 0; i < n; i++) {
            printf("%d: %s", i, history[i].command);
            for (int j = 0; j < history[i].num_args; j++) {
                printf(" %s", history[i].args[j]);
            }
            printf("\n");
        }
    } else {
        printf("Invalid usage of hist command.\n");
    }
}

void comand(Command* cmd) {
    if (cmd->num_args == 1) {
        int n = atoi(cmd->args[0]);
        if (n >= 0 && n < history_size) {
            execute_command(&history[n]);
        } else {
            printf("Invalid argument for comand.\n");
        }
    } else {
        printf("Invalid usage of comand command.\n");
    }
}

void open_command(Command* cmd) {
    if (cmd->num_args == 2) {
        const char* filename = cmd->args[0];
        const char* mode = cmd->args[1];

        int flags = 0;
        if (strcmp(mode, "cr") == 0) {
            flags = O_CREAT | O_RDWR;
        } else if (strcmp(mode, "ap") == 0) {
            flags = O_APPEND | O_RDWR;
        } else if (strcmp(mode, "ex") == 0) {
            flags = O_CREAT | O_EXCL | O_RDWR;
        } else if (strcmp(mode, "ro") == 0) {
            flags = O_RDONLY;
        } else if (strcmp(mode, "rw") == 0) {
            flags = O_RDWR;
        } else if (strcmp(mode, "wo") == 0) {
            flags = O_WRONLY;
        } else if (strcmp(mode, "tr") == 0) {
            flags = O_CREAT | O_TRUNC | O_RDWR;
        } else {
            printf("Invalid mode for open command.\n");
            return;
        }

        int fd = open(filename, flags, S_IRUSR | S_IWUSR);
        if (fd == -1) {
            perror("open");
            return;
        }

        // Add the file to the list of open files
        if (open_files_count < MAX_HISTORY_SIZE) {
            OpenFile new_open_file;
            new_open_file.fd = fd;
            strcpy(new_open_file.filename, filename);
            strcpy(new_open_file.mode, mode);
            open_files[open_files_count] = new_open_file;
            open_files_count++;
            printf("Opened file %s with mode %s (fd: %d)\n", filename, mode, fd);
        } else {
            printf("Maximum number of open files reached.\n");
            close(fd);
        }
    } else {
        printf("Invalid usage of open command.\n");
    }
}

void close_command(Command* cmd) {
    if (cmd->num_args == 1) {
        int df = atoi(cmd->args[0]);
        if (df >= 0 && df < open_files_count) {
            int fd_to_close = open_files[df].fd;
            if (close(fd_to_close) == 0) {
                printf("Closed file descriptor %d\n", df);
                // Remove the closed file from the list
                for (int i = df; i < open_files_count - 1; i++) {
                    open_files[i] = open_files[i + 1];
                }
                open_files_count--;
            } else {
                perror("close");
            }
        } else {
            printf("Invalid file descriptor for close command.\n");
        }
    } else {
        printf("Invalid usage of close command.\n");
    }
}

void dup_command(Command* cmd) {
    if (cmd->num_args == 1) {
        int df = atoi(cmd->args[0]);
        if (df >= 0 && df < open_files_count) {
            int new_fd = dup(open_files[df].fd);
            if (new_fd == -1) {
                perror("dup");
            } else {
                // Add the duplicated file to the list
                if (open_files_count < MAX_HISTORY_SIZE) {
                    OpenFile new_open_file;
                    new_open_file.fd = new_fd;
                    strcpy(new_open_file.filename, open_files[df].filename);
                    strcpy(new_open_file.mode, open_files[df].mode);
                    open_files[open_files_count] = new_open_file;
                    open_files_count++;
                    printf("Duplicated file descriptor %d to %d\n", df, new_fd);
                } else {
                    printf("Maximum number of open files reached.\n");
                    close(new_fd);
                }
            }
        } else {
            printf("Invalid file descriptor for dup command.\n");
        }
    } else {
        printf("Invalid usage of dup command.\n");
    }
}

void listopen(void) {
    printf("Open Files:\n");
    for (int i = 0; i < open_files_count; i++) {
        printf("Descriptor: %d, File: %s, Mode: %s\n", i, open_files[i].filename, open_files[i].mode);
    }
}

void infosys(void) {
#ifdef __linux__
    struct utsname info;
    if (uname(&info) != -1) {
        printf("System Information:\n");
        printf("Operating System: %s\n", info.sysname);
        printf("Node Name: %s\n", info.nodename);
        printf("Release: %s\n", info.release);
        printf("Version: %s\n", info.version);
        printf("Machine: %s\n", info.machine);
    } else {
        perror("uname");
    }
#else
    printf("System information is not available on Windows.\n");
#endif
}



void create_command(Command* cmd) {
    if (cmd->num_args != 1) {
        printf("Usage: create [file/directory]\n");
        return;
    }

    const char* path = cmd->args[0];

    if (strstr(path, ".txt") != NULL) {
        FILE* file = fopen(path, "w");
        if (file == NULL) {
            perror("create");
        } else {
            fclose(file);
            printf("File created successfully at %s\n", path);
        }
    } else {
        if (mkdir(path, 0777) == -1) {
            perror("create");
        } else {
            printf("Directory created successfully at %s\n", path);
        }
    }

}

void stat_command(Command* cmd) {
    if (cmd->num_args != 1) {
        printf("Usage: stat [file/directory]\n");
        return;
    }

    const char* path = cmd->args[0];
    struct stat fileStat;

    if (stat(path, &fileStat) == -1) {
        perror("stat");
    } else {
        printf("Information for %s\n", path);
        printf("Size: %ld\n", fileStat.st_size);
        printf("Permissions: %s\n", ConvierteModo2(fileStat.st_mode));
    }
}

void print_file_info(const char* path, struct dirent* ent, const ListOptions* opts) {
    char fullpath[1024];
    struct stat statbuf;

    snprintf(fullpath, sizeof(fullpath), "%s/%s", path, ent->d_name);

    if (lstat(fullpath, &statbuf) == -1) {
        perror("lstat");
        return;
    }

    // Omitir archivos ocultos si no está activada la opción -hid
    if (!opts->hidden_files && ent->d_name[0] == '.') {
        return;
    }

    // Para la opción -link, mostrar solo si es un enlace simbólico
    if (opts->show_links && !S_ISLNK(statbuf.st_mode)) {
        return;
    }

    if (opts->long_format) {
        char time_str[20];
        time_t time = opts->access_time ? statbuf.st_atime : statbuf.st_mtime;
        strftime(time_str, sizeof(time_str), "%b %d %H:%M", localtime(&time));
        printf("%10ld %s %s\n", statbuf.st_size, time_str, ent->d_name);
    } else {
        printf("%s\n", ent->d_name);
    }
}



int compare_access_time(const struct dirent** a, const struct dirent** b) {
    struct stat sta, stb;
    stat((*a)->d_name, &sta);
    stat((*b)->d_name, &stb);
    return sta.st_atime - stb.st_atime;
}

void list_directory(const char* path, const ListOptions* opts) {
    struct dirent **namelist;
    int n;

    if (opts->access_time) {
        n = scandir(path, &namelist, NULL, compare_access_time);
    } else {
        n = scandir(path, &namelist, NULL, alphasort);
    }

    if (n < 0) {
        perror("scandir");
    } else {
        while (n--) {
            print_file_info(path, namelist[n], opts);
            free(namelist[n]);

            // Manejar recursividad
            if (opts->recursive && namelist[n]->d_type == DT_DIR && strcmp(namelist[n]->d_name, ".") != 0 && strcmp(namelist[n]->d_name, "..") != 0) {
                char newpath[1024];
                snprintf(newpath, sizeof(newpath), "%s/%s", path, namelist[n]->d_name);
                list_directory(newpath, opts); // Llamada recursiva
            }
        }
        free(namelist);
    }
}

void list_command(Command* cmd) {
    ListOptions opts = {0, 0, 0, 0, 0};
    const char* path = "."; // Directorio actual por defecto

    for (int i = 0; i < cmd->num_args; ++i) {
        if (strcmp(cmd->args[i], "-long") == 0 || strcmp(cmd->args[i], "-l") == 0) {
            opts.long_format = 1;
        } else if (strcmp(cmd->args[i], "-acc") == 0) {
            opts.access_time = 1;
        } else if (strcmp(cmd->args[i], "-link") == 0 || strcmp(cmd->args[i], "-L") == 0) {
            opts.show_links = 1;
        } else if (strcmp(cmd->args[i], "-hid") == 0 || strcmp(cmd->args[i], "-h") == 0) {
            opts.hidden_files = 1;
        } else if (strcmp(cmd->args[i], "-reca") == 0 || strcmp(cmd->args[i], "-recb") == 0 || strcmp(cmd->args[i], "-R") == 0) {
            opts.recursive = 1;
        } else {
            path = cmd->args[i]; // Considera el último argumento como el path si no es una opción
        }
    }

    list_directory(path, &opts);
}

void delete_command(Command* cmd) {
    if (cmd->num_args != 1) {
        printf("Usage: delete [file/directory]\n");
        return;
    }

    const char* path = cmd->args[0];
    if (remove(path) == -1) {
        perror("delete error");
        printf("Error description: %s\n", strerror(errno));
    } else {
        printf("File/Directory deleted successfully: %s\n", path);
    }
}

void deltree_command(Command* cmd) {
    if (cmd->num_args != 1) {
        printf("Usage: deltree [directory]\n");
        return;
    }

    const char* path = cmd->args[0];
    DIR *d = opendir(path);

    if (!d) {
        perror("opendir");
        return;
    }

    struct dirent *p;
    while ((p = readdir(d)) != NULL) {
        if (strcmp(p->d_name, ".") == 0 || strcmp(p->d_name, "..") == 0) {
            continue;
        }

        size_t len = strlen(path) + strlen(p->d_name) + 2;
        char *buf = malloc(len);
        if (buf) {
            snprintf(buf, len, "%s/%s", path, p->d_name);
            struct stat statbuf;
            if (!stat(buf, &statbuf)) {
                if (S_ISDIR(statbuf.st_mode)) {
                    Command del_cmd;
                    del_cmd.num_args = 1;
                    strcpy(del_cmd.command, "deltree");
                    strcpy(del_cmd.args[0], buf);
                    deltree_command(&del_cmd);
                } else {
                    if (unlink(buf) < 0) {
                        perror("unlink");
                    }
                }
            }
            free(buf);
        }
    }
    closedir(d);

    if (rmdir(path) < 0) {
        perror("rmdir");
    } else {
        printf("Directory deleted successfully: %s\n", path);
    }
}

//CAMBIO




void malloc_command(Command* cmd) {
    if (cmd->num_args == 1) {
        size_t size = (size_t) atoi(cmd->args[0]);
        void* ptr = malloc(size);
        if (ptr == NULL) {
            perror("malloc");
            return;
        }

        MemoryBlock* new_block = malloc(sizeof(MemoryBlock));
        if (new_block == NULL) {
            perror("malloc - MemoryBlock");
            free(ptr);
            return;
        }

        new_block->address = ptr;
        new_block->size = size;
        new_block->allocation_time = time(NULL);
        new_block->type = MALLOC;
        new_block->next = memory_blocks;
        memory_blocks = new_block;

        printf("Bloque de memoria asignado en %p\n", ptr);
    } else if (cmd->num_args == 2 && strcmp(cmd->args[0], "-free") == 0) {
        void* addr = (void*)strtoul(cmd->args[1], NULL, 0);
        liberarBloqueMemoria(addr);
    } else {
        printf("Uso incorrecto del comando malloc.\n");
    }
}


void shared_command(Command* cmd) {
    key_t key;
    int shm_id;
    void* shm_addr;

    if (cmd->num_args < 2) {
        printf("Uso incorrecto del comando shared. Necesitas al menos 2 argumentos.\n");
        return;
    }

    key = atoi(cmd->args[1]);

    if (strcmp(cmd->args[0], "-create") == 0 && cmd->num_args == 3) {
        size_t size = atoi(cmd->args[2]);
        shm_id = shmget(key, size, IPC_CREAT | IPC_EXCL | 0666);
        if (shm_id == -1) {
            perror("shmget");
            return;
        }
        shm_addr = shmat(shm_id, NULL, 0);
        if (shm_addr == (void*) -1) {
            perror("shmat");
            return;
        }

        MemoryBlock* new_block = malloc(sizeof(MemoryBlock));
        if (new_block == NULL) {
            perror("malloc - MemoryBlock");
            shmdt(shm_addr);
            return;
        }

        new_block->address = shm_addr;
        new_block->size = size;
        new_block->allocation_time = time(NULL);
        new_block->type = SHARED;
        new_block->key = key;
        new_block->next = memory_blocks;
        memory_blocks = new_block;

        printf("Bloque de memoria compartida asignado en %p\n", shm_addr);
    } else if (strcmp(cmd->args[0], "-free") == 0) {
        // Implementar lógica de liberación
    } else if (strcmp(cmd->args[0], "-delkey") == 0) {
        shm_id = shmget(key, 0, 0666);
        if (shm_id == -1) {
            perror("shmget");
            return;
        }
        if (shmctl(shm_id, IPC_RMID, NULL) == -1) {
            perror("shmctl");
            return;
        }
        // Actualizar lista de bloques de memoria (eliminar el bloque correspondiente)
    } else {
        printf("Opción no reconocida o faltan argumentos.\n");
    }
}




void mmap_command(Command* cmd) {
    if (cmd->num_args < 2) {
        printf("Uso incorrecto del comando mmap. Se requiere al menos un nombre de fichero y permisos.\n");
        return;
    }

    const char* filename = cmd->args[1];
    int fd, flags = 0;
    struct stat st;
    void* map;

    if (strcmp(cmd->args[0], "-free") == 0) {
        // Implementar lógica para desmapear el archivo y actualizar la lista
    } else {
        fd = open(filename, O_RDONLY);
        if (fd == -1) {
            perror("open");
            return;
        }

        if (fstat(fd, &st) == -1) {
            perror("fstat");
            close(fd);
            return;
        }

        if (strcmp(cmd->args[0], "r") == 0) flags = PROT_READ;
        else if (strcmp(cmd->args[0], "w") == 0) flags = PROT_WRITE;
        else if (strcmp(cmd->args[0], "x") == 0) flags = PROT_EXEC;
        else {
            printf("Permisos no válidos. Utilice 'r', 'w', o 'x'.\n");
            close(fd);
            return;
        }

        map = mmap(NULL, st.st_size, flags, MAP_PRIVATE, fd, 0);
        if (map == MAP_FAILED) {
            perror("mmap");
            close(fd);
            return;
        }

        MemoryBlock* new_block = malloc(sizeof(MemoryBlock));
        if (new_block == NULL) {
            perror("malloc - MemoryBlock");
            munmap(map, st.st_size);
            close(fd);
            return;
        }

        new_block->address = map;
        new_block->size = st.st_size;
        new_block->allocation_time = time(NULL);
        new_block->type = MMAP;
        strncpy(new_block->filename, filename, sizeof(new_block->filename));
        new_block->fd = fd;
        new_block->next = memory_blocks;
        memory_blocks = new_block;

        printf("Archivo mapeado en memoria en %p\n", map);
        close(fd);
    }
}





void read_command(Command* cmd) {
    if (cmd->num_args != 3) {
        printf("Uso: read fichero posición cantidad\n");
        return;
    }

    const char* filename = cmd->args[0];
    off_t pos = strtoul(cmd->args[1], NULL, 0); // Posición en el archivo
    size_t count = atoi(cmd->args[2]);

    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }

    if (lseek(fd, pos, SEEK_SET) == -1) {
        perror("lseek");
        close(fd);
        return;
    }

    char* buffer = malloc(count);
    if (buffer == NULL) {
        perror("malloc");
        close(fd);
        return;
    }

    ssize_t bytes_read = read(fd, buffer, count);
    if (bytes_read == -1) {
        perror("read");
        free(buffer);
        close(fd);
        return;
    }

    printf("Datos leídos: ");
    for (ssize_t i = 0; i < bytes_read; ++i) {
        printf("%02x ", (unsigned char)buffer[i]);
    }
    printf("\n");

    free(buffer);
    close(fd);
    printf("Leídos %ld bytes desde %s a la posición 0x%lx\n", bytes_read, filename, (unsigned long)pos);
}



void write_command(Command* cmd) {
    if (cmd->num_args < 3) {
        printf("Uso: write [-o] fichero dirección cantidad\n");
        return;
    }

    int overwrite = 0;
    int arg_offset = 0;
    if (strcmp(cmd->args[0], "-o") == 0) {
        overwrite = 1;
        arg_offset = 1;
    }

    const char* filename = cmd->args[arg_offset];
    void* addr = (void*)strtoul(cmd->args[arg_offset + 1], NULL, 0);
    int count = atoi(cmd->args[arg_offset + 2]);

    // Validación básica de la dirección
    if (addr == NULL) {
        printf("Dirección de memoria inválida.\n");
        return;
    }

    int flags = overwrite ? (O_WRONLY | O_CREAT | O_TRUNC) : (O_WRONLY | O_CREAT | O_APPEND);
    int fd = open(filename, flags, 0666);
    if (fd == -1) {
        perror("open");
        return;
    }

    ssize_t bytes_written = write(fd, addr, count);
    if (bytes_written == -1) {
        perror("write");
        close(fd);
        return;
    }

    close(fd);
    printf("Escritos %ld bytes desde 0x%p a %s\n", bytes_written, addr, filename);
}


void memdump_command(Command* cmd) {
    if (cmd->num_args != 2) {
        printf("Uso: memdump dirección cantidad\n");
        return;
    }

    unsigned char* addr = (unsigned char*)strtoul(cmd->args[0], NULL, 0);
    int count = atoi(cmd->args[1]);

    if (addr == NULL || count <= 0) {
        printf("Argumentos inválidos para memdump.\n");
        return;
    }

    printf("Volcado de memoria desde 0x%p, %d bytes:\n", addr, count);
    for (int i = 0; i < count; ++i) {
        if (i % 16 == 0) printf("\n0x%p: ", addr + i);
        printf("%02x ", addr[i]);
    }
    printf("\n");
}


void memfill_command(Command* cmd) {
    if (cmd->num_args != 3) {
        printf("Uso: memfill dirección cantidad byte\n");
        return;
    }

    void* addr = (void*)strtoul(cmd->args[0], NULL, 0);
    int count = atoi(cmd->args[1]);
    int byte = atoi(cmd->args[2]);

    if (addr == NULL || count <= 0) {
        printf("Argumentos inválidos para memfill.\n");
        return;
    }

    // Verificar si el byte proporcionado está en el rango de un carácter
    if (byte < 0 || byte > 255) {
        printf("El byte debe estar entre 0 y 255.\n");
        return;
    }

    // Comprobación del rango de memoria
    if (!esDireccionValida(addr, count)) {
        printf("Rango de memoria fuera de los límites.\n");
        return;
    }

    printf("Llenando memoria desde 0x%p, %d bytes, con 0x%02x\n", addr, count, byte);
    memset(addr, byte, count);
}


void mem_command(Command* cmd) {
    if (cmd->num_args != 0) {
        for (int i = 0; i < cmd->num_args; i++) {
            if (strcmp(cmd->args[i], "-vars") == 0) {
                // Variables automáticas y estáticas
                auto int autoVar1 = 0, autoVar2 = 0, autoVar3 = 0;
                static int staticVar1 = 0, staticVar2 = 0, staticVar3 = 0;

                printf("Variables automáticas: %p, %p, %p\n", &autoVar1, &autoVar2, &autoVar3);
                printf("Variables estáticas: %p, %p, %p\n", &staticVar1, &staticVar2, &staticVar3);
                printf("Variables globales: %p, %p, %p, %p\n", &input_buffer, &output_buffer, &history_size, &open_files_count);

            } else if (strcmp(cmd->args[i], "-funcs") == 0) {
                printf("Funciones del programa: %p, %p, %p, %p, %p, ...\n", execute_command, authors, pid, chdir_command, date);
                printf("Funciones de la biblioteca: %p, %p, %p, ...\n", malloc, printf, strcmp);

            } else if (strcmp(cmd->args[i], "-blocks") == 0) {
                MemoryBlock* current = memory_blocks;
                while (current != NULL) {
                    printf("Bloque de memoria: %p, Tamaño: %zu\n", current->address, current->size);
                    current = current->next;
                }

            } else if (strcmp(cmd->args[i], "-all") == 0) {
                Command allCmd;
                allCmd.num_args = 3;
                strcpy(allCmd.args[0], "-vars");
                strcpy(allCmd.args[1], "-funcs");
                strcpy(allCmd.args[2], "-blocks");
                mem_command(&allCmd);

            } else if (strcmp(cmd->args[i], "-pmap") == 0) {
                dopmap();
            }
        }
    } else {
        Command defaultCmd;
        defaultCmd.num_args = 1;
        strcpy(defaultCmd.args[0], "-all");
        mem_command(&defaultCmd);
    }
}





void recursive_function(int n) {
    char array[2048];  // Array de tamaño fijo para demostrar el uso de la pila

    printf("Llamada %d: dirección de array %p\n", n, &array);
    if (n > 1) {
        recursive_function(n - 1);
    }
}

void recurse_command(Command* cmd) {
    if (cmd->num_args != 1) {
        printf("Uso: recurse [n]\n");
        return;
    }

    int n = atoi(cmd->args[0]);
    if (n <= 0) {
        printf("El número de llamadas recursivas debe ser positivo.\n");
        return;
    }

    if (n > MAX_RECURSION_DEPTH) {
        printf("Número de llamadas recursivas excede el límite seguro de %d.\n", MAX_RECURSION_DEPTH);
        return;
    }

    printf("Iniciando recursión con %d llamadas...\n", n);
    recursive_function(n);
}


void liberarBloqueMemoria(void* addr) {
    MemoryBlock **current = &memory_blocks, *temp;
    while (*current != NULL) {
        if ((*current)->address == addr) {
            temp = *current;
            *current = (*current)->next;

            if (temp->type == MALLOC) {
                free(temp->address);
            } else if (temp->type == SHARED) {
                shmdt(temp->address);
                // La eliminación de la clave SHM (si es necesario) debería hacerse en otra parte
            } else if (temp->type == MMAP) {
                munmap(temp->address, temp->size);
                // Cerrar el archivo si es necesario
                if (temp->fd != -1) {
                    close(temp->fd);
                }
            }

            free(temp);
            printf("Memoria liberada en la dirección %p\n", addr);
            return;
        }
        current = &(*current)->next;
    }
    printf("No se encontró un bloque de memoria con la dirección %p\n", addr);
}


int esDireccionValida(void *addr, size_t count) {
    MemoryBlock* current = memory_blocks;
    while (current != NULL) {
        if (addr >= current->address && (char*)addr + count <= (char*)current->address + current->size) {
            return 1; // La dirección está dentro de un bloque asignado
        }
        current = current->next;
    }
    return 0; // No se encontró la dirección en los bloques asignados
}


void dopmap(void) {
    pid_t pid;
    char elpid[32];
    char *argv[3] = {"pmap", elpid, NULL};

    sprintf(elpid, "%d", (int)getpid());

    if ((pid = fork()) == -1) {
        perror("Imposible crear proceso");
        return;
    }

    if (pid == 0) {
        if (execvp(argv[0], argv) == -1) {
            perror("Cannot execute pmap");
            exit(1);
        }
    }

    waitpid(pid, NULL, 0);
}



void help(Command* cmd) {
    if (cmd->num_args == 0) {
        printf("Available Commands:\n");
        printf("authors [-l|-n]\n");
        printf("pid [-p]\n");
        printf("chdir [dir]\n");
        printf("date\n");
        printf("time\n");
        printf("hist [-c|-N]\n");
        printf("comand N\n");
        printf("open [file] mode\n");
        printf("close [df]\n");
        printf("dup [df]\n");
        printf("listopen\n");
        printf("infosys\n");
        printf("create [file/directory]\n");
        printf("stat [file/directory]\n");
        printf("list [directory]\n");
        printf("delete [file/directory]\n");
        printf("deltree [directory]\n");
        printf("help [cmd]\n");
        printf("quit\n");
        printf("exit\n");
        printf("bye\n");
        printf("malloc [size|-free address]\n");
        printf("shared [-create key size|-free address|-delkey key]\n");
        printf("mmap [-free address|permissions filename]\n");
        printf("read [file address size]\n");
        printf("write [-o] [file address size]\n");
        printf("memdump [address size]\n");
        printf("memfill [address size byte]\n");
        printf("mem [-vars|-funcs|-blocks|-all|-pmap]\n");
        printf("recurse [n]\n");
    } else if (cmd->num_args == 1) {
        char* command_name = cmd->args[0];
        if (strcmp(command_name, "authors") == 0) {
            printf("authors [-l|-n]: Prints the names and logins of the program authors.\n");
        } else if (strcmp(command_name, "pid") == 0) {
            printf("pid [-p]: Prints the PID of the shell process or its parent's PID.\n");
        } else if (strcmp(command_name, "chdir") == 0) {
            printf("chdir [dir]: Changes the current working directory to 'dir' or prints the current directory.\n");
        } else if (strcmp(command_name, "date") == 0) {
            printf("date: Prints the current date in the format DD/MM/YYYY.\n");
        } else if (strcmp(command_name, "time") == 0) {
            printf("time: Prints the current time in the format hh:mm:ss.\n");
        } else if (strcmp(command_name, "hist") == 0) {
            printf("hist [-c|-N]: Shows or clears the command history or lists the first N commands.\n");
        } else if (strcmp(command_name, "comand") == 0) {
            printf("comand N: Repeats command number N from the command history.\n");
        } else if (strcmp(command_name, "open") == 0) {
            printf("open [file] mode: Opens a file with the specified mode.\n");
        } else if (strcmp(command_name, "close") == 0) {
            printf("close [df]: Closes a file descriptor.\n");
        } else if (strcmp(command_name, "dup") == 0) {
            printf("dup [df]: Duplicates a file descriptor.\n");
        } else if (strcmp(command_name, "listopen") == 0) {
            printf("listopen: Lists open files and their descriptors.\n");
        } else if (strcmp(command_name, "infosys") == 0) {
            printf("infosys: Prints information about the system.\n");
        } else if (strcmp(command_name, "create") == 0) {
            printf("create [file/directory]: Creates a file or directory.\n");
        } else if (strcmp(command_name, "stat") == 0) {
            printf("stat [file/directory]: Gives information on files or directories.\n");
        } else if (strcmp(command_name, "list") == 0) {
            printf("list [directory]: Lists the contents of a directory.\n");
        } else if (strcmp(command_name, "delete") == 0) {
            printf("delete [file/directory]: Deletes a file or directory.\n");
        } else if (strcmp(command_name, "deltree") == 0) {
            printf("deltree [directory]: Deletes files or non-empty directories recursively.\n");
        } else if (strcmp(command_name, "help") == 0) {
            printf("help [cmd]: Displays help information for a specific command.\n");
        } else if (strcmp(command_name, "quit") == 0 || strcmp(command_name, "exit") == 0 || strcmp(command_name, "bye") == 0) {
            printf("quit, exit, bye: Exits the shell.\n");
        }else if (strcmp(command_name, "malloc") == 0) {
            printf("malloc [size|-free address]: Allocates memory or frees allocated memory.\n");
        } else if (strcmp(command_name, "shared") == 0) {
            printf("shared [-create key size|-free address|-delkey key]: Manages shared memory segments.\n");
        } else if (strcmp(command_name, "mmap") == 0) {
            printf("mmap [-free address|permissions filename]: Maps or unmaps files into memory.\n");
        } else if (strcmp(command_name, "read") == 0) {
            printf("read [file address size]: Reads data from a file to a memory address.\n");
        } else if (strcmp(command_name, "write") == 0) {
            printf("write [-o] [file address size]: Writes data from a memory address to a file.\n");
        } else if (strcmp(command_name, "memdump") == 0) {
            printf("memdump [address size]: Dumps memory contents from a specified address.\n");
        } else if (strcmp(command_name, "memfill") == 0) {
            printf("memfill [address size byte]: Fills memory with a specific byte value.\n");
        } else if (strcmp(command_name, "mem") == 0) {
            printf("mem [-vars|-funcs|-blocks|-all|-pmap]: Displays memory related information.\n");
        } else if (strcmp(command_name, "recurse") == 0) {
            printf("recurse [n]: Executes a function recursively n times.\n");

        } else {
            printf("Unknown command: %s\n", command_name);
        }
    } else {
        printf("Invalid usage of help command.\n");
    }
}

