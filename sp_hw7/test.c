#include <unistd.h>
#include <stdio.h>
int main()
{
    char name[0x10] = "\%p";
    printf(name);
}
