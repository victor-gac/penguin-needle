#include <stdio.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <unistd.h>

int main(int argc, char **arv) {
   char* handle = dlopen("libname.so", RTLD_NOW | RTLD_GLOBAL);
   if(!handle)
      printf("Could not find libname\n");
  return 0;
}
