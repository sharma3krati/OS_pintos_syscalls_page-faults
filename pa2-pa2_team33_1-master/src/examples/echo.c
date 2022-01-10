#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  //int i;
  typedef int (* volatile functionptr)(void);
  for (i = 0; i < argc; i++)
   printf ("%s ", argv[i]);
  //printf ("\n");
  //printf ("Congratulations - you have successfully dereferenced NULL: %d", 
    //    *(volatile int *) NULL);
  //return EXIT_SUCCESS;
}
