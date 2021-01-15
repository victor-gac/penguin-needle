#define __GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <time.h>

#define CHUNK_SIZE 512

// libname
//static const char *libname = "/data/local/tmp/samplelib.so";
static const char* libname = "libname.so";

// text seen in /proc/<pid>/maps for text areas
static const char* text_area = " r-xp ";

// this should be a string that will uniquely identify libc in /proc/<pid>/maps
static const char* libc_string = "/libc";

// find the location of a shared library in memory
void* find_library(pid_t pid, const char* libname) {
  char filename[32];
  snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
  FILE* f = fopen(filename, "r");
  char* line = NULL;
  size_t line_size = 0;

  while (getline(&line, &line_size, f) >= 0) {
    char *pos = strstr(line, libname);
    if (pos != NULL && strstr(line, text_area)) {
      char* val = (char*) strtoul(line, NULL, 16);
      free(line);
      fclose(f);
      return (void *)val;
    }
  }
  free(line);
  fclose(f);
  return NULL;
}

void quit(char* error) {
   perror(error);
   exit(1);
}

void poke_chunk(pid_t target, void* addr, void* src, size_t size) {
   uint8_t data;
   size_t i = 0;
   for(i = 0; i < size; i += sizeof(data)) {
      memcpy(&data, src + i, sizeof(data));
      if(ptrace(PTRACE_POKETEXT, target, addr + i, (void*) data) == -1)
         quit("PTRACE_POKETEXT");
   }
}

void peek_chunk(pid_t target, void* addr, void* dest, size_t size) {
   uint8_t data;
   size_t i = 0;
   for(i = 0; i < size; i += sizeof(data)) {
      data = ptrace(PTRACE_PEEKTEXT, target, addr + i, NULL);
      if(data == -1)
         quit("PTRACE_PEEKTEXT");
      memcpy(dest + i, &data, sizeof(data));
   }
}

int main(int argc, char** argv) {
   pid_t target = atoi(argv[1]);
   int waitpidstatus;

   struct user_regs_struct regs, saved_regs;
   memset(&regs, 0, sizeof(struct user_regs_struct));
   memset(&saved_regs, 0, sizeof(struct user_regs_struct));

   int8_t backup[CHUNK_SIZE], code[CHUNK_SIZE];
   memset(&backup, 0, sizeof(int8_t)*CHUNK_SIZE);
   memset(&code, 0, sizeof(int8_t)*CHUNK_SIZE);

   /* Attach to the process */
   if(ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1)
      quit("PTRACE_ATTACH");
   waitpid(target, &waitpidstatus, 0);

   /* Attach to the process */
   if(ptrace(PTRACE_SETOPTIONS, target, NULL, PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACESYSGOOD) == -1)
      quit("PTRACE_SETOPTIONS");

   /* Get and save registers */
   if(ptrace(PTRACE_GETREGS, target, NULL, &regs) == -1)
      quit("PTRACE_GETREGS");
   memcpy(&saved_regs, &regs, sizeof(struct user_regs_struct));
   printf("esp %p, eip %p\n", (void*) regs.esp, (void*) regs.eip);

   /* Build stackframe */
   memcpy(code + CHUNK_SIZE/2, libname, strlen(libname));
   int offset = 0;

   size_t word = 0x0;
   memcpy(code + offset, &word, sizeof(size_t));   // Return address set to one will provoke SIGSEGV
   offset += sizeof(size_t);
 
   size_t addr = regs.esp + CHUNK_SIZE/2;
   memcpy(code + offset, &addr, sizeof(size_t));   // Address of the string argument
   offset += sizeof(size_t);

   //size_t flag = RTLD_NOW | RTLD_GLOBAL;
   size_t flag = RTLD_NOW | RTLD_GLOBAL;
   memcpy(code + offset, &flag, sizeof(size_t));   // Flags

   /* Save first chunk of stack frame */
   peek_chunk(target, (void*) regs.esp, backup, CHUNK_SIZE);

   /* Inject our own stackframe */
   poke_chunk(target, (void*) regs.esp, code, CHUNK_SIZE);
 
   /* Look for libc address */
   void* loc_libc_addr = find_library(getpid(), libc_string);
   void* target_libc_addr = find_library(target, libc_string);
   printf("local libc         %p\n", loc_libc_addr);
   printf("target libc        %p\n", target_libc_addr);

   /* Look for dlopen address __libc_dlopen_mode
   can also get it simply: char* addr = (char*)printf; */
   char* loc_dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
   if(loc_dlopen_addr) 
      printf("dlopen found at    %p\n", loc_dlopen_addr);
   /* Deduce address of dlopen in target context */
   void* target_dlopen_addr = target_libc_addr + ((void*)loc_dlopen_addr - loc_libc_addr);
   printf("dlopen target at   %p\n", target_dlopen_addr);

   /* Hijack execution flow */
   regs.eip = (size_t) target_dlopen_addr + 2;
   printf("esp %p, eip %p\n", (void*) regs.esp, (void*) regs.eip);
   if(ptrace(PTRACE_SETREGS, target, NULL, &regs) == -1)
       quit("PTRACE_SETREGS");

   /* Since fake return address will provoke a SIGSEGV, we wait for it */
   int step = 0; // debug
   do {
      if(ptrace(PTRACE_SINGLESTEP, target, NULL, NULL) == -1)
         quit("PTRACE_SINGLESTEP");
      waitpid(target, &waitpidstatus, 0);
      step++; // debug
   } while(!(WIFSTOPPED(waitpidstatus) && WSTOPSIG(waitpidstatus) == SIGSEGV));
   printf("%d steps\n", step); // debug

   if(ptrace(PTRACE_GETREGS, target, NULL, &regs) == -1)
      quit("PTRACE_GETREGS");
   printf("esp %p, eip %p, eax %p\n", (void*) regs.esp, (void*) regs.eip, (void*) regs.eax);

   /* Restore stack */
   poke_chunk(target, (void*) saved_regs.esp, backup, CHUNK_SIZE);
   /* Restore registers */
   if(ptrace(PTRACE_SETREGS, target, NULL, &saved_regs) == -1)
       quit("PTRACE_SETREGS");
   /* Detach from the proces */
   if(ptrace(PTRACE_DETACH, target, NULL, NULL) == -1)
       quit("PTRACE_DETACH");

   while(getchar() != '\n')
      ;
}
