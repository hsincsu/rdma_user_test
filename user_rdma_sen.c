//#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <malloc.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <time.h>
#include <inttypes.h>

#include <infiniband/verbs.h>

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
		union  ibv_gid			*gid;
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
};

struct addr_info{
		char *remote_addr;
		uint64_t size;
		uint64_t rkey;
};

struct qp_info{
		uint32_t qpn;
		uint32_t qkey;
		uint32_t pkey;
		union ibv_gid gid;
		//uint8_t dmac[6];
		struct addr_info addr;	
};


static void usage(const char *argv0)
{
        printf("Usage:\n");
        printf("  %s            start a server and wait for connection\n", argv0);
        printf("  %s <host>     connect to server at <host>\n", argv0);
        printf("\n");
        printf("Options:\n");
        printf("  -p, --port=<port>      listen on/connect to port <port> (default 18515)\n");
        printf("  -i, --ib-port=<port>   use port <port> of IB device (default 1)\n");
        printf("  -s, --size=<size>      size of message to exchange (default 4096)\n");
        printf("  -g, --gid-idx=<gid index> local port gid index\n");
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

	//get opt
	unsigned int port = 8888;
	int 	  ib_port = 1;
	unsigned int size = 4096;
	int       	 gidx = 2;
	char  *servername = NULL;

	while(1){
		 int c;
		 static struct option long_options[] = {
                        { .name = "port",     .has_arg = 1, .val = 'p' },
                        { .name = "ib-port",  .has_arg = 1, .val = 'i' },
                        { .name = "size",     .has_arg = 1, .val = 's' },
                        { .name = "gid-idx",  .has_arg = 1, .val = 'g' },
                        {}
                };
		 c = getopt_long(argc,argv,"p:i:s:g:",long_options,NULL);

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

	ib_dev = *dev_list;
	if(!ib_dev)
	{
		printf("dwcrdma-user: ib_dev null \n");
	}
	
	


	ctx1 = calloc(1,sizeof *ctx1);
	page_size = sysconf(_SC_PAGESIZE);
	ctx1->buf = memalign(page_size, size);

	memcpy(ctx1->buf,"hello,world",12);
	printf("buf: 0x%s \n",ctx1->buf);

	printf("dwcrdma-user:ibv_open_device \n");
    ctx1->context = ibv_open_device(ib_dev);

        
	printf("dwcrdma-user:oepn success \n");
	ctx1->pd = ibv_alloc_pd(ctx1->context);

	printf("dwcrdma-user:alloc pd success \n");		
	ctx1->mr = ibv_reg_mr(ctx1->pd, ctx1->buf, size, access_flags);

	printf("dwcrdma-user:reg mr success \n");
	ctx1->cq_s.cq = ibv_create_cq(ctx1->context,100, NULL,NULL,0);

	printf("dwcrdma-user:create_cq success\n");
	struct ibv_qp_attr attr;
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

	//alloc buf
	struct qp_info *qpinfo = NULL;
    struct qp_info *qpinfo_c = NULL;
    int qpinfosize = sizeof(*qpinfo);
    qpinfo_c = malloc(sizeof(*qpinfo_c));
    qpinfo = malloc(sizeof(*qpinfo));
    memset(qpinfo,0,sizeof(*qpinfo));
    memset(qpinfo_c,0,sizeof(*qpinfo_c));

	qpinfo->qpn = ctx1->qp->qp_num;
	qpinfo->qkey = 0;
	qpinfo->pkey = 0;



    struct ibv_qp_attr attr3 = {
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

	union ibv_gid gid;
	ret = ibv_query_gid(ctx1->context, ib_port, gidx, ctx1->gid);




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
