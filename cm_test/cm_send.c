#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/mman.h>
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
#define PRINT_MAC	   (unsigned int) 6

#define PRINT_CM	   (unsigned int) 3
#define PRINT_PGU	   (unsigned int) 4
#define PRINT_PHD	   (unsigned int) 5
#define DESTROY_ADDR   (unsigned int) 7
#define GET_REG        (unsigned int) 8

ioctl_operation(int cmd, int *buf)
{
    int fd;
    
    fd = open("/dev/cm_rw",O_RDWR);
    if(fd < 0){
        printf("can't open /dev/cm_rw \n");
        return ;
    }
    ioctl(fd,cmd,buf);    
    close(fd);

}

int main(int argc, char *argv[])
{
    int fd;
    uint64_t buf[7];
    int buflen;
    int data;    
    int choose = 0;
    char *ipaddr;

    ipaddr = malloc(sizeof(8));
    if(argc >= 2)
    ipaddr = strdup(argv[1]);
    else
    {
        ipaddr = "127.0.0.1";
    }
    printf("destipaddr = %s \n",ipaddr);

while(1){
    printf("\n");
    printf("---------------------------------------------------------\n");
    printf("| welcome to debug sys in sysfs(later change to debugfs)|\n");
    printf("| 1. CM SEND                                            |\n");
    printf("| 2. CM RECV                                            |\n");
    printf("| 3. PRINT MAC(use dmesg to check)                      |\n");
    printf("| 4. GET KERNEL DMA ADDR                                |\n");
    printf("| 5. READ KERNEL ADDR VALUE                             |\n");
    printf("| 6. WRITE KERNEL ADDR VALUE                            |\n");
    printf("| 7. destroy dma addr                                   |\n");
    printf("| 8. get reg                                            |\n");
    printf("| 9. mmapfun                                            |\n");
    printf("| other function may support later                      |\n");
    printf("| 10. exit                                               |\n");
    printf("---------------------------------------------------------\n");

    while(1){
    printf("please choose:");
    if(scanf("%d",&choose) == 1 && choose > 0)
    {
    if(1 <= choose && 10 >= choose )
        break;
    else
    {
        printf("please choose with number(1-8)\n");
    }
    }
    else
    {
        printf("wrong input \n");
    } 
    setbuf(stdin,NULL); //flush stdin space
    }

    buf[0] = ntohl(inet_addr(ipaddr));

    switch(choose)
    {
        case 1:
        {
            printf("cm send \n");
            ioctl_operation(KERNEL_CM_SEND,(int *)buf);break;
        }
        case 2:
        {
            printf("cm recv \n");
            ioctl_operation(KERNEL_CM_RECV,(int *)buf);break;
        }
        case 3:
        {
            printf("print mac \n");
            ioctl_operation(PRINT_MAC,(int *)buf);break;
        }
        case 4:
        {
            printf("get kernel dma addr\n");
            ioctl_operation(PRINT_CM,(int *)buf);
            printf("dma addr:%lx\n",buf[2]);break;
        }
        case 5:
        {
            printf("read kernel addr \n");
            ioctl_operation(PRINT_PGU,(int *)buf);
            printf("read value : %d\n",buf[3]);break;
        }
        case 6:
        {
            printf("write kernel addr\n");
            printf("write(integer):");
            scanf("%d",&buf[4]);
            ioctl_operation(PRINT_PHD,(int *)buf);break;
        }
        case 7:
        {
            ioctl_operation(DESTROY_ADDR,(int *)buf);break;
        }
        case 8:
        {
            printf("write reg addr\n");
            printf("write(integer):");
            scanf("%x",&buf[5]);
            printf("regaddr:0x%x\n",buf[5]);
            ioctl_operation(GET_REG,(int *)buf);
            printf("regval:0x%x\n",buf[6]);
            break;
        }
        case 9:
        {
        int i = 1;
        int fd;
        uint64_t phyaddr;
        uint8_t *addr;
        fd = open("/dev/cm_rw",O_RDWR);
        if(fd < 0){
            printf("can't open /dev/cm_rw \n");
            return ;
            }
        printf("please enter phyaddr\n");
        scanf("%x",&phyaddr);
        addr = mmap(NULL,phyaddr,PROT_READ|PORT_WRITE,MAP_SHARED,fd,4096);
        if(addr == MAP_FAILED)
            break;
        
        do{
            printf("(1-continue,0-exit:\n");
            scanf("%d",&i);

            printf("write val \n");
            scanf(addr);

        }while(1);
        close(fd);
        }
        default:
            break;
    }
    if(choose == 10)
        break;

    }

    return 0;
}