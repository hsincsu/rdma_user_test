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
#define PRINT_MAC	   (unsigned int) 2

int main(int argc, char *argv[])
{
    int fd;
    int buf[4];
    int buflen;
    int data;

    buf[0] = ntohl(inet_addr("10.0.0.5"));
    fd = open("/dev/cm_rw",O_RDWR);
    if(fd < 0){
        printf("can't open /dev/cm_rw \n");
        return;
    }

    int choose;

while(1){
    printf("welcome to debug sys in sysfs(later change to debugfs):");
    printf("1. CM SEND\n");
    printf("2. CM RECV\n");
    printf("3. PRINT MAC(use dmesg to check)\n");
    printf("4. exit\n");
    printf("please choose:");
    scanf("%d \n",&choose);

    switch(choose)
    {
        case 1:
        {
            ioctl(fd,KERNEL_CM_SEND,buf);
        }
        case 2:
        {
            ioctl(fd,KERNEL_CM_RECV,buf);
        }
        case 3:
        {
            ioctl(fd,PRINT_MAC,buf);
        }
        default:
        break;
    }
    if(choose == 4)
        break;

    }

    //ioctl(fd,KERNEL_CM_SEND,buf);
    close(fd);
    return 0;
}