
#include <stdio.h>

static inline int min(int a, int b) { return a<b ? a : b; }

int main ()
{
   printf ("min de 6, 3 : %d\n", min(6,3));
}
