#include <stdlib.h>
int main(){
    char buf[0x10];
    __read_chk( 0 , buf , 0xf , 0x10 );
    printf("%d\n", atoi( buf ));
}
