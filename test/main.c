#include <stdio.h>

int foo(){
    printf("ye duniya, ye duniya pittal di");
    return 10;
}

int main(){
    int secret = foo();
    printf("%d\n", secret);
    return 0;
}