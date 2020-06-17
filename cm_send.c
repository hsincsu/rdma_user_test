#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>

#include <asm/ioctls.h>
#include <netdb.h>
#include <malloc.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <time.h>
#include <inttypes.h>

#include <infiniband/verbs.h>


#define KERNEL_CM_SEND (unsigned int) 0
#define KERNEL_CM_RECV (unsigned int) 1

int main(int argc, char *argv[])
{
    int fd;
    int buf[4];
    int buflen;
    int data;

    buf[0] = 12345;
    fd = open("/dev/cm_rw",O_RDWR);
    if(fd < 0){
        printf("can't open /dev/cm_rw \n");
        return;
    }

    ioctl(fd,KERNEL_CM_SEND,buf);
    close(fd);
    return 0;
}