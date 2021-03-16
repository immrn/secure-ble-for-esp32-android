#include <stdio.h>
#include "mytestcomp.h"

#include "mytestcomp2.h"

void func(int a, int b)
{
    printf("%i + %i = %i!\n",a,b,add(a,b));
}
