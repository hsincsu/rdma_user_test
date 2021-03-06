//#include <config.h>

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
#define PRINT_MAC	   (unsigned int) 6

#define PRINT_CM	   (unsigned int) 3
#define PRINT_PGU	   (unsigned int) 4
#define PRINT_PHD	   (unsigned int) 5
#define DESTROY_ADDR   (unsigned int) 7

#define strdupa(_s)                                             \
({                                                              \
        char *_d;                                               \
        int _len;                                               \
                                                                \
        _len = strlen(_s) + 1;                                  \
        _d = alloca(_len);                                      \
        if (_d)                                                 \
                memcpy(_d, _s, _len);                           \
        _d;                                                     \
})   


struct pingpong_context { 
        struct ibv_context      *context;
        struct ibv_comp_channel *channel;
        struct ibv_pd           *pd;
        struct ibv_mr           *mr;
        struct ibv_dm           *dm;
		union  ibv_gid			gid;
		char 					*servername;
		unsigned int 			port;
		int 	  				ib_port;
		int       	 			gidx;
		int						client;
		int						mode;
        union {
                struct ibv_cq           *cq;
                struct ibv_cq_ex        *cq_ex;
        } cq_s;
        struct ibv_qp           *qp;
        char                    *buf;
        int                      size;
        int                      send_flags;
        int                      rx_depth;
        int                      pending;
        struct ibv_port_attr     portinfo;
        uint64_t                 completion_timestamp_mask;


        uint64_t                 dmaaddr;
};

struct addr_info{
		char *remote_addr;
		uint64_t dmaaddr;
		uint64_t size;
		uint64_t rkey;
}__attribute__ ((packed));;

struct qp_info{
		uint32_t qpn;
		uint32_t qkey;
		uint32_t pkey;
		union ibv_gid gid;
		//uint8_t dmac[6];
		struct addr_info addr;	
}__attribute__ ((packed));;


static void usage(const char *argv0)
{
        printf("Usage:\n");
        printf("  %s <addr to bind>           start a server and wait for connection\n", argv0);
        printf("  %s <host>     connect to server at <host>\n", argv0);
        printf("\n");
        printf("Options:\n");
        printf("  -p, --port=<port>      listen on/connect to port <port> (default 18515)\n");
        printf("  -i, --ib-port=<port>   use port <port> of IB device (default 1)\n");
		printf("  -d, --ib-dev=<str> 	 ib_device 's name that you 'll use\n");
        printf("  -s, --size=<size>      size of message to exchange (default 4096)\n");
        printf("  -g, --gid-idx=<gid index> local port gid index\n");
		printf("  -c, --client=(0/1)	 0-for server mode(default), 1-for client mode\n");
		printf("  -m, --mode=(0/1)		 0-RDMA_WRITE, 1-SEND/RECV\n");
}


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



int start_my_server(struct pingpong_context *ctx,char *send_buf,int sendsize ,char *recv_buf,int recvsize)
{
		int sockfd, connfd;
		struct sockaddr_in clienaddr;
		int recvlen;

		printf("start server socket\n");
		if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
    	printf("create socket error: %s(errno: %d)\n", strerror(errno),errno);
    	exit(0);
    	}

		printf("socket create success\n");
		memset(&clienaddr,0,sizeof(clienaddr));
		clienaddr.sin_family = AF_INET;
		clienaddr.sin_port 	 = htons(ctx->port);
		clienaddr.sin_addr.s_addr = inet_addr(ctx->servername);

		if(bind(sockfd,(struct sockaddr *)&clienaddr,sizeof(clienaddr)) == -1)
		{
			 printf("bind socket error:%s(errno:%d)\n",strerror(errno),errno);
        	 exit(0);
		}
		printf("bind ok\n");

	  	if(listen(sockfd,10) == -1)
		{
			printf("listen socket error:%s(errno:%d)\n",strerror(errno),errno);
			exit(0);
		}
		printf("listen ok\n");
		while(1){
			if((connfd = accept(sockfd,(struct sockaddr *)NULL, NULL)) == -1){
				printf("accept socket error :%s(errno:%d)\n",strerror(errno),errno);
            	continue;
			}
			printf("accept ok\n");

			recvlen = recv(connfd,recv_buf,recvsize,0);
			if(0 >= recvlen)
				{printf("recv error\n");exit(0);}
			else
			{
				printf("recv sucess \n");break;
			}
			
		}

		if(send(connfd,send_buf,sendsize,0) < 0)
		{
			printf("send msg error\n");
			exit(0);
		}
		printf("send success\n");
		
		close(connfd);
		close(sockfd);

		return 0;

}



int start_my_client(struct pingpong_context *ctx,char *send_buf,int sendsize ,char *recv_buf,int recvsize)
{
		int sockfd, n;
		struct sockaddr_in servaddr;
		int	 recvlen;

		printf("client socket start \n");
		if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
    	printf("create socket error: %s(errno: %d)\n", strerror(errno),errno);
    	exit(0);
    	}
		
		printf("socket create ok\n");
		memset(&servaddr, 0, sizeof(servaddr));
		servaddr.sin_family = AF_INET;
		servaddr.sin_port 	= htons(ctx->port);
		if(inet_pton(AF_INET,ctx->servername,&servaddr.sin_addr.s_addr) <= 0){
			printf("inet_pton error\n");
    		exit(0);
		}

		if(connect(sockfd,(struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
			printf("connect error: %s(errno: %d)\n",strerror(errno),errno);
    		exit(0);
		}

		printf("socket connect ok \n");
		printf("client: send ..\n");
		if(send(sockfd,send_buf,sendsize,0) < 0)
		{
			printf("send msg error\n");
			exit(0);
		}
		printf("client: send success\n");

		recvlen = recv(sockfd,recv_buf,recvsize,0);
		if(0 >= recvlen)
			printf("recv error\n");
		else{
			printf("recv success\n");
		}

		close(sockfd);
		return 0;
}



int main(int argc, char *argv[])
{
	struct ibv_device      **dev_list;
    struct ibv_device       *ib_dev;
	struct pingpong_context  *ctx1;
	static int page_size;
	//int size = 4096;
	int access_flags = IBV_ACCESS_REMOTE_READ|IBV_ACCESS_REMOTE_WRITE|IBV_ACCESS_LOCAL_WRITE;
	int ret = 0;
	int i =0; 

	//get opt
	unsigned int port = 8888;
	int 	  ib_port = 1;
	unsigned int size = 17;
	int       	 gidx = 2;
	int 		client= 0;
	int			mode  = 0;
	char  *servername = NULL;
	char  *ib_devname = NULL;

	while(1){
		 int c;
		 static struct option long_options[] = {
                        { .name = "port",     .has_arg = 1, .val = 'p' },
                        { .name = "ib-port",  .has_arg = 1, .val = 'i' },
                        { .name = "size",     .has_arg = 1, .val = 's' },
                        { .name = "gid-idx",  .has_arg = 1, .val = 'g' },
						{ .name = "client",   .has_arg = 1, .val = 'c' },
						{ .name = "ib-dev",	  .has_arg = 1, .val = 'd' },
						{ .name = "mode",	  .has_arg = 1, .val = 'm' },
                        {}
                };
		 c = getopt_long(argc,argv,"p:i:s:g:c:d:m:",long_options,NULL);

		 if(c == -1)
		 	break;
		 
		 switch(c){
			 case 'p':
			 		port = strtoul(optarg, NULL, 0);
					if(port > 65535){
						 usage(argv[0]);
						 return 1;
					}
					break;
		 	 case 'i':
			  		ib_port = strtol(optarg, NULL, 0);
					  if(ib_port < 1){
						  usage(argv[0]);
						  return 1;
					  }
					  break;
			 case 's':
			 		size = strtoul(optarg, NULL, 0);
					 break;
			 case 'g':
			 		gidx = strtol(optarg, NULL, 0);
					printf("gidx :%d \n",gidx);
					 break;
			 case 'c':
			 		client = strtoul(optarg,NULL,0);
					printf("client: 0x%x\n",client);
					break;
			 case 'd':
					ib_devname = strdupa(optarg);
					break;
			 case 'm':
					mode = strtol(optarg,NULL,0);
					break;
			 default:
			 		usage(argv[0]);
					 return 1;
		 }

	}

	if(optind == argc - 1)
			servername = strdupa(argv[optind]);
	else if (optind < argc){
			usage(argv[0]);
			return 1;
	}
	
	if(servername == NULL)
	{printf("sorry, client and server all need ipaddr to bind.server need local addr\n");return 1;}
	printf("check param...  \n");
	printf("port : 0x%x \n", port);
	printf("ib_port: 0x%x \n", ib_port);
	printf("size: 0x%x \n",size);
	printf("gidx: 0x%x \n",gidx);
	printf("servername: %s\n",servername);


	dev_list = ibv_get_device_list(NULL);
	if(!dev_list){
		printf("dwcrdma-user: NULL device list \n");
		return 1;
	}

	if (!ib_devname) {
                ib_dev = *dev_list;
                if (!ib_dev) {
                        fprintf(stderr, "No IB devices found\n");
                        return 1;
                }
        } else {
                for (i = 0; dev_list[i]; ++i)
                        if (!strcmp(ibv_get_device_name(dev_list[i]), ib_devname))
                                break;
                ib_dev = dev_list[i];
                if (!ib_dev) {
                        fprintf(stderr, "IB device %s not found\n", ib_devname);
                        return 1;
                }
        }
	


	ctx1 = calloc(1,sizeof *ctx1);
	ctx1->mode		 = mode;
	ctx1->port 		 = port;
	ctx1->ib_port 	 = ib_port;
	ctx1->gidx 		 = gidx;
	ctx1->servername = servername;
	ctx1->client	 = client;
	page_size 		 = sysconf(_SC_PAGESIZE);


	ctx1->buf 		 = malloc(size);//memalign(page_size, size);
	ctx1->size 		 = size;
	memset(ctx1->buf,0,size);
	if(ctx1->client == 1)
	memcpy(ctx1->buf,"hello,world",12);
	printf("buf: %s \n",ctx1->buf);

    /*get kernel dma addr to test*/
    uint64_t buf[5];
    memset(buf,0,sizeof(buf));
    
    ioctl_operation(PRINT_CM,(int *)buf);
    ctx1->dmaaddr = buf[2];
    printf("dma addr: 0x%lx\n",ctx1->dmaaddr);

    if(ctx1->client == 1)
    {
        printf("client write kernel addr\n");
        printf("write(int): ");
        scanf("%d",&buf[4]);
        ioctl_operation(PRINT_PHD,(int *)buf);
    }

    /* end of kernel dma addr*/

	printf("dwcrdma-user:ibv_open_device \n");
    ctx1->context = ibv_open_device(ib_dev);

        
	printf("dwcrdma-user:oepn success \n");
	ctx1->pd = ibv_alloc_pd(ctx1->context);

	printf("dwcrdma-user:alloc pd success \n");		
	ctx1->mr = ibv_reg_mr(ctx1->pd, ctx1->buf, size, access_flags);

	printf("dwcrdma-user:reg mr success \n");
	ctx1->cq_s.cq = ibv_create_cq(ctx1->context,100, NULL,NULL,0);

	printf("dwcrdma-user:create_cq success\n");
                struct ibv_qp_init_attr init_attr = {
                        .send_cq = ctx1->cq_s.cq,
                        .recv_cq = ctx1->cq_s.cq,
                        .cap     = {
                                .max_send_wr  = 10,
                                .max_recv_wr  = 10,
                                .max_send_sge = 1,
                                .max_recv_sge = 1
                        },
                        .qp_type = IBV_QPT_RC
                };
	ctx1->qp = ibv_create_qp(ctx1->pd, &init_attr);
	printf("dwcrdma-user: create qp success \n");

    struct ibv_qp_attr attr = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = 1,
			.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ |
                              IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_ATOMIC
		};

    if (ibv_modify_qp(ctx1->qp, &attr,
				  IBV_QP_STATE              |
				  IBV_QP_PKEY_INDEX         |
				  IBV_QP_PORT               |
				  IBV_QP_ACCESS_FLAGS)) {
			fprintf(stderr, "Failed to modify QP to INIT\n");
            goto clean_qp;
                  }
	printf("modify qp init success\n");

	//In init we can post recv first
	if(ctx1->client == 0)
{
	if(ctx1->mode == 0)
	{
		printf("In RDMA WRITE\n");
	}

	if(ctx1->mode == 1)
	{
		printf("In SEND/RECV");
		struct ibv_sge list = {
				.addr 	= ctx1->dmaaddr,
				.length = ctx1->size,
				.lkey	= ctx1->mr->lkey 
		};

		struct ibv_recv_wr wr= {
				.wr_id		=3,
				.sg_list 	= &list,
				.num_sge 	= 1,
		};

		struct ibv_recv_wr *bad_wr;
		if(ibv_post_recv(ctx1->qp, &wr, &bad_wr))
		{
				fprintf(stderr, "Couldn't post recv\n");
				return 1;
		}
		printf("post success\n");

	}
}




	ret = ibv_query_gid(ctx1->context, ib_port, gidx, &ctx1->gid);

	printf("query gid success\n");

	struct qp_info *qpinfo = NULL;
    struct qp_info *qpinfo_r = NULL;
	printf("sizeof qpinfo:0x%x\n",sizeof(*qpinfo));
    int qpinfosize = sizeof(*qpinfo);
    qpinfo_r = malloc(sizeof(*qpinfo_r));
    qpinfo = malloc(sizeof(*qpinfo));
    memset(qpinfo,0,sizeof(*qpinfo));
    memset(qpinfo_r,0,sizeof(*qpinfo_r));

	qpinfo->qpn = ctx1->qp->qp_num;
	qpinfo->qkey = 0;
	qpinfo->pkey = 0;
	qpinfo->addr.remote_addr = ctx1->buf;
	qpinfo->addr.dmaaddr 	 = ctx1->dmaaddr;
	qpinfo->addr.size 		 = ctx1->size;
	qpinfo->addr.rkey		 = ctx1->mr->rkey;
	memcpy(&qpinfo->gid,&ctx1->gid,sizeof(union ibv_gid));

	printf("client: qpn : 0x%x \n",qpinfo->qpn);
    printf("client: addr : 0x%lx \n",qpinfo->addr.remote_addr);
	printf("client: dmaaddr : 0x%lx \n",qpinfo->addr.dmaaddr);
    printf("client: size : 0x%lx \n",qpinfo->addr.size);
    printf("client: rkey : 0x%lx \n",qpinfo->addr.rkey);


	printf("start socket\n");
if(ctx1->client == 1){
	start_my_client(ctx1,(char *)qpinfo,qpinfosize,(char *)qpinfo_r,qpinfosize);
	printf("server's qpinfo : \n");
	printf("gid:");
    for(i =0;i<16;i++)
    printf("%x",qpinfo_r->gid.raw[i]);
    printf("server: qpn:0x %x \n",qpinfo_r->qpn);
    printf("server: qkey:0x %x \n",qpinfo_r->qkey);
    printf("server: pkey: 0x %x \n",qpinfo_r->pkey);
    printf("server: addr : 0x%lx \n",qpinfo_r->addr.remote_addr);
	printf("server: dmaaddr : 0x%lx \n",qpinfo_r->addr.dmaaddr);
    printf("server: size : 0x%lx \n",qpinfo_r->addr.size);
    printf("server: rkey : 0x%lx \n",qpinfo_r->addr.rkey);
	 printf("gid:");
    for(i =0;i<16;i++)
    printf("%x",qpinfo_r->gid.raw[i]);
}
else
{
	start_my_server(ctx1,(char *)qpinfo,qpinfosize,(char *)qpinfo_r,qpinfosize);
	printf("client's qpinfo : \n");
 	printf("gid:");
    for(i =0;i<16;i++)
    printf("%x",qpinfo_r->gid.raw[i]);

    printf("client: qpn:0x %x \n",qpinfo_r->qpn);
    printf("client: qkey:0x %x \n",qpinfo_r->qkey);
    printf("client: pkey: 0x %x \n",qpinfo_r->pkey);
    printf("client: addr : 0x%lx \n",qpinfo_r->addr.remote_addr);
	printf("client: dmaaddr : 0x%lx \n",qpinfo_r->addr.dmaaddr);
    printf("client: size : 0x%lx \n",qpinfo_r->addr.size);
    printf("client: rkey : 0x%lx \n",qpinfo_r->addr.rkey);
	
}

	memset(&attr,0,sizeof(attr));

	attr.qp_state               = IBV_QPS_RTR;
    attr.path_mtu               = IBV_MTU_1024;
    attr.dest_qp_num            = qpinfo_r->qpn;
    attr.rq_psn                 = 0;
    attr.max_dest_rd_atomic     = 1;
    attr.min_rnr_timer          = 12;
	attr.ah_attr.is_global		= 1,
    attr.ah_attr.sl             = 0;
    attr.ah_attr.port_num       = ctx1->ib_port;
	attr.ah_attr.grh.dgid		= qpinfo_r->gid;
	attr.ah_attr.grh.hop_limit  = 1;
    attr.ah_attr.grh.sgid_index = ctx1->gidx;

	if (ibv_modify_qp(ctx1->qp, &attr,
                          IBV_QP_STATE              |
                          IBV_QP_AV                 |
                          IBV_QP_PATH_MTU           |
                          IBV_QP_DEST_QPN           |
                          IBV_QP_RQ_PSN             |
                          IBV_QP_MAX_DEST_RD_ATOMIC |
                          IBV_QP_MIN_RNR_TIMER)) {
                fprintf(stderr, "Failed to modify QP to RTR\n");
                return 1;
        }
	


		attr.qp_state       = IBV_QPS_RTS;
        attr.timeout        = 14;
        attr.retry_cnt      = 7;
        attr.rnr_retry      = 6;
        attr.sq_psn         = 0;
        attr.max_rd_atomic  = 1;


	if (ibv_modify_qp(ctx1->qp, &attr,
						IBV_QP_STATE              |
						IBV_QP_TIMEOUT            |
						IBV_QP_RETRY_CNT          |
						IBV_QP_RNR_RETRY          |
						IBV_QP_SQ_PSN             |
						IBV_QP_MAX_QP_RD_ATOMIC)) {
			fprintf(stderr, "Failed to modify QP to RTS\n");
			return 1;
	}


if(ctx1->client == 1)
{
	if(ctx1->mode == 0){
	printf("In RDMA WRITE \n");
	struct ibv_sge list;
	struct ibv_send_wr wr;
	struct ibv_send_wr *bad_wr;

	memset(&list,0,sizeof(list));
	list.addr 	=  ctx1->dmaaddr;
	list.length	=  ctx1->size;
	list.lkey	=  ctx1->mr->lkey;

	memset(&wr,0,sizeof(wr));
	wr.wr_id		= 	1;
	wr.sg_list		= 	&list;
	wr.num_sge		=   1;
	wr.opcode		=   IBV_WR_RDMA_WRITE;
	wr.send_flags 	= 	IBV_SEND_SIGNALED;
	wr.wr.rdma.remote_addr = qpinfo_r->addr.dmaaddr;//(uintptr_t)qpinfo_r->addr.remote_addr;
	wr.wr.rdma.rkey	= 	qpinfo_r->addr.rkey;

	if(ibv_post_send(ctx1->qp,&wr,&bad_wr))
	{
		fprintf(stderr, "Couldn't post send\n");
        return 1;
	}
	printf("post success \n");
	}
	
	if(ctx1->mode == 1)
	{
		printf("In SEND/RECV \n");
		struct ibv_sge list;
		struct ibv_send_wr wr;
		struct ibv_send_wr *bad_wr;

		memset(&list,0,sizeof(list));
		list.addr 	=  ctx1->dmaaddr;
		list.length	=  ctx1->size;
		list.lkey	=  ctx1->mr->lkey;

		memset(&wr,0,sizeof(wr));
		wr.wr_id		= 2;
		wr.sg_list		= &list;
		wr.num_sge		= 1;
		wr.opcode		= IBV_WR_SEND;
		wr.send_flags 	= IBV_SEND_SIGNALED;

		if(ibv_post_send(ctx1->qp,&wr,&bad_wr))
		{
			fprintf(stderr, "Couldn't post send\n");
        	return 1;
		} 
		printf("post success \n");
	}
}


	struct ibv_wc wc;
	if(ibv_poll_cq(ctx1->cq_s.cq,1,&wc) >= 0)
	{
		printf("poll success\n");
	}
	else{
		printf("poll wrong\n");
		return 1;
	}

	printf("buf: %s \n",ctx1->buf);

	ioctl_operation(PRINT_PGU,(int *)buf);
	printf("kernel buf: %d\n",buf[3]);
if(ctx1->client == 0)
	{printf("wait 5 seconds to read\n");sleep(1);}

	printf("buf wait: %s \n",ctx1->buf);


	ioctl_operation(PRINT_PGU,(int *)buf);
	printf("kernel buf wait: %d\n",buf[3]);


clean_qp:
	ibv_destroy_qp(ctx1->qp);
	ibv_destroy_cq(ctx1->cq_s.cq);
	ibv_dereg_mr(ctx1->mr);
	ibv_dealloc_pd(ctx1->pd);
	ibv_close_device(ctx1->context);
	free(ctx1->buf);
	free(ctx1);

	return 0;
}
