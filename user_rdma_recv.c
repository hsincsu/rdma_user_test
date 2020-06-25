//#include <config.h>

/*this file is not used right now ,my alter it later. but now function is not completed*/












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

struct pingpong_context { 
        struct ibv_context      *context;
        struct ibv_comp_channel *channel;
        struct ibv_pd           *pd;
        struct ibv_mr           *mr;
        struct ibv_dm           *dm;
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


struct pingpong_context *ctx1;
struct pingpong_context *ctx2;
struct ibv_pd *pd1;
struct ibv_pd *pd2;
struct ibv_cq *cq1;
struct ibv_cq *cq2;
struct ibv_mr *mr1;
struct ibv_mr *mr2;
struct ibv_qp *qp1;
struct ibv_qp *qp2;


int main(int argc, char *argv[])
{
	struct ibv_device      **dev_list;
        struct ibv_device       *ib_dev;
	static int page_size;
	int size = 4096;
	int access_flags = IBV_ACCESS_LOCAL_WRITE;

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
	ctx2 = calloc(1,sizeof *ctx2);
	page_size = sysconf(_SC_PAGESIZE);
	ctx1->buf = memalign(page_size, size);
	memset(ctx1->buf, 0x7b, size);
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
                                .max_send_wr  = 1,
                                .max_recv_wr  = 99,
                                .max_send_sge = 1,
                                .max_recv_sge = 1
                        },
                        .qp_type = IBV_QPT_RC
                };
	ctx1->qp = ibv_create_qp(ctx1->pd, &init_attr);
	printf("dwcrdma-user: create qp success \n");
	
	int i;
again:	printf("please enter!");
	scanf("%d",&i);	
	printf("have enter:%d",i);
	if(i == -1){
	ibv_destroy_qp(ctx1->qp);
	ibv_destroy_cq(ctx1->cq_s.cq);
	ibv_dereg_mr(ctx1->mr);
	ibv_dealloc_pd(ctx1->pd);
	ibv_close_device(ctx1->context);
	free(ctx1->buf);
	free(ctx1);
	free(ctx2);
	}
	else
	  goto  again;
	return 0;
}
