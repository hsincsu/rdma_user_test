#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include<linux/socket.h>
#include<net/sock.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/parser.h>
#include <linux/proc_fs.h>
#include <linux/inet.h>
#include <linux/list.h>
#include <linux/in.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/time.h>
#include <linux/random.h>
#include <linux/signal.h>
#include <linux/proc_fs.h>

#include <asm/atomic.h>
#include <asm/pci.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include "getopt.h"

static int debug = 1;
#define DEBUG_LOG if (debug) printk
#define BUFFER_SIZE 1024

MODULE_VERSION("1.0.0.0");
MODULE_AUTHOR("HS");
MODULE_DESCRIPTION("KERNEL RDMA TEST");
MODULE_LICENSE("Dual BSD/GPL");

static const struct krdma_option krdma_opts[] = {
	{"count", OPT_INT, 'C'},
	{"size", OPT_INT, 'S'},
	{"addr", OPT_STRING, 'a'},
	{"addr6", OPT_STRING, 'A'},
	{"port", OPT_INT, 'p'},
	{"verbose", OPT_NOPARAM, 'v'},
	{"validate", OPT_NOPARAM, 'V'},
	{"server", OPT_NOPARAM, 's'},
	{"client", OPT_NOPARAM, 'c'},
	{"server_inv", OPT_NOPARAM, 'I'},
 	{"wlat", OPT_NOPARAM, 'l'},
 	{"rlat", OPT_NOPARAM, 'L'},
 	{"bw", OPT_NOPARAM, 'B'},
 	{"duplex", OPT_NOPARAM, 'd'},
	{"tos", OPT_INT, 't'},
 	{"txdepth", OPT_INT, 'T'},
 	{"poll", OPT_NOPARAM, 'P'},
 	{"local_dma_lkey", OPT_NOPARAM, 'Z'},
 	{"read_inv", OPT_NOPARAM, 'R'},
 	{"fr", OPT_NOPARAM, 'f'},
	{NULL, 0, 0}
};



struct krdma_stats {
	unsigned long long send_bytes;
	unsigned long long send_msgs;
	unsigned long long recv_bytes;
	unsigned long long recv_msgs;
	unsigned long long write_bytes;
	unsigned long long write_msgs;
	unsigned long long read_bytes;
	unsigned long long read_msgs;
};

#define htonll(x) cpu_to_be64((x))
#define ntohll(x) cpu_to_be64((x))

static DEFINE_MUTEX(krdma_mutex);

static LIST_HEAD(krdma_cbs);

static struct proc_dir_entry *krdma_proc;

enum test_state {
	IDLE = 1,
	CONNECT_REQUEST,
	ADDR_RESOLVED,
	ROUTE_RESOLVED,
	CONNECTED,
	RDMA_READ_ADV,
	RDMA_READ_COMPLETE,
	RDMA_WRITE_ADV,
	RDMA_WRITE_COMPLETE,
	ERROR
};



struct krdma_buf_info{
        uint64_t *buf;
        uint32_t rkey;
        uint32_t size;
};


struct krdma_cb{
        int server;
        struct ib_pd *pd;
        struct ib_cq *cq;
        struct ib_qp *qp;

        struct ib_mr *dma_mr;
        struct ib_mr *reg_mr;

        int server_invalidate;
	    int read_inv;
        u8 key;

        struct ib_recv_wr rq_wr;
        struct ib_sge recv_sg1;
        struct krdma_buf_info recv_buf __aligned(16);
        u64 recv_dma_addr;


        struct ib_send_wr sg_wr;
        struct ib_sge send_sg1;
        struct krdma_buf_info send_buf __aligned(16);
        u64 send_dma_addr;
        struct ib_mr *rdma_mr; // for send mr.

        uint32_t remote_rkey;
        uint64_t remote_addr;
        uint32_t remote_len;

        char *start_buf;
        u64   start_dma_addr;
        struct ib_mr *start_mr;

        enum test_state state;
        wait_queue_head_t sem;
        struct krdma_stats stats;

        uint16_t port;
        u8 addr[16];
        char *addr_str;
        uint8_t addr_type;
        int verbose;
        int count;
        int size;
        int validate;
        int wlat;
        int rlat;
        int bw;
        int duplex;
        int poll;
        int txdepth;
        int local_dma_lkey;
        int frtest;			/* reg test */
	    int tos;			/* type of service */

        //just user rdma_cm_id to find the ib_device,we don't need rdma_connect to exchange info.because we don't support it now.
        struct rdma_cm_id *cm_id;	/* connection on client side,*/
					/* listener on server side. */
	    struct rdma_cm_id *child_cm_id;	/* connection on server side */

        struct list_head list;

};

int start_my_server(struct krdma_cb *cb){
    struct socket *sock, *client_sock;
    struct sockaddr_in s_addr;
    unsigned short port = 0;

    int ret = 0;

    port = cb->port;

    memset(&s_addr,0,sizeof(s_addr));
    s_addr.sin_family=AF_INET;
    s_addr.sin_port  =port;
    s_addr.sin_addr.s_addr = htonl(cb->addr); // bind the card addr.

    sock = (struct socket *)kmalloc(sizeof(struct socket),GFP_KERNEL);
    client_sock = (struct socket *)kmalloc(sizeof(struct socket),GFP_KERNEL);

    ret = sock_create_kern(&init_net,AF_INET, SOCK_STREAM, 0, &sock);
    if(ret){
            printk("server: socket create error \n");
    }
    printk("server: socket create ok \n");

    ret = sock->ops->bind(sock,(struct sockaddr *)&s_addr, sizeof(struct sockaddr_in));
    if(ret < 0){
            printk("server: bind error\n");
            return ret;
    }
    printk("server: bind ok\n");

    ret = sock->ops->listen(sock,10);
    if(ret< 0){
            printk("server: listen error \n");
            return ret;
    }
    printk("server: listen ok \n");

    ret = kernel_accept(sock,&client_sock,10);
    if(ret < 0){
            printk("server: accept error\n");
            return ret;
    }
    printk("server: accept, connection established\n");

    char *recvbuf = NULL;
    recvbuf = kmalloc(1024,GFP_KERNEL);
    if(recvbuf == NULL)
    {
        printk("server: recvbuf kmalloc failed \n");
        return -1;
    }
    memset(recvbuf,0,1024);

    struct kvec vec;
    struct msghdr msg;
    memset(&vec,0,sizeof(vec));
	memset(&msg,0,sizeof(msg));

    vec.iov_base = recvbuf;
    vec.iov_len  = 1024;
    msg.msg_flags= MSG_NOSIGNAL;
    msleep(1000);
   
    ret=kernel_recvmsg(client_sock,&msg,&vec,1,1024, msg.msg_flags); /*receive message*/  
    recvbuf[1023] = 0;
    printk("receive message:\n %s\n",recvbuf);

    printk("release socket now\n");
    sock_release(client_sock);
    sock_release(sock);

    return ret;

}

int start_my_client(struct krdma_cb *cb){
    struct socket *sock;
    struct sockaddr_in s_addr;
    unsigned short port_num = 0;
    int ret = 0;
    char *send_buf = NULL;
    char *recv_buf = NULL;
    struct kvec send_vec, recv_vec;
    struct msghdr send_msg, recv_msg;


    port_num = cb->port;

    /* kmalloc a send buffer*/
    send_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    if (send_buf == NULL) {
        printk("client: send_buf kmalloc error!\n");
        return -1;
    }
    /* kmalloc a receive buffer*/
    recv_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    if(recv_buf == NULL){
        printk("client: recv_buf kmalloc error!\n");
        return -1;
    }
    memset(&s_addr, 0, sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = port_num;
    s_addr.sin_addr.s_addr = htonl(cb->addr);
    sock = (struct socket *)kmalloc(sizeof(struct socket), GFP_KERNEL);
    
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (ret < 0) {
        printk("client:socket create error!\n");
        return ret;
    }
    printk("client: socket create ok!\n");
  
    ret = sock->ops->connect(sock, (struct sockaddr *)&s_addr, sizeof(s_addr), 0);
    if (ret != 0) {
        printk("client: connect error!\n");
        return ret;
    }
    printk("client: connect ok!\n");
    memset(send_buf, 'a', BUFFER_SIZE);
    memset(&send_msg, 0, sizeof(send_msg));
    memset(&send_vec, 0, sizeof(send_vec));
    send_vec.iov_base = send_buf;
    send_vec.iov_len = BUFFER_SIZE;
    // 发送数据
    ret = kernel_sendmsg(sock, &send_msg, &send_vec, 1, BUFFER_SIZE);
    if (ret < 0) {
        printk("client: kernel_sendmsg error!\n");
        return ret;
    } else if(ret != BUFFER_SIZE){
        printk("client: ret!=BUFFER_SIZE");
    }
    printk("client: send ok!\n");
    memset(recv_buf, 0, BUFFER_SIZE);
    memset(&recv_vec, 0, sizeof(recv_vec));
    memset(&recv_msg, 0, sizeof(recv_msg));
    recv_vec.iov_base = recv_buf;
    recv_vec.iov_len = BUFFER_SIZE;
    // 接收数据
    ret = kernel_recvmsg(sock, &recv_msg, &recv_vec, 1, BUFFER_SIZE, 0);
    printk("client: received message:\n %s\n", recv_buf);
    // 关闭连接
    kernel_sock_shutdown(sock, SHUT_RDWR);
    sock_release(sock);
    return 0;
}




static int reg_supported(struct ib_device *dev)
{
	u64 needed_flags = IB_DEVICE_MEM_MGT_EXTENSIONS;

	if ((dev->attrs.device_cap_flags & needed_flags) != needed_flags) {
		printk( "Fastreg not supported - device_cap_flags 0x%llx\n",
			(unsigned long long)dev->attrs.device_cap_flags);
		return 0;
	}
	DEBUG_LOG("Fastreg supported - device_cap_flags 0x%llx\n",
		(unsigned long long)dev->attrs.device_cap_flags);
	return 1;
}


static void fill_sockaddr(struct sockaddr_storage *sin, struct krdma_cb *cb)
{
	memset(sin, 0, sizeof(*sin));

	if (cb->addr_type == AF_INET) {
		struct sockaddr_in *sin4 = (struct sockaddr_in *)sin;
		sin4->sin_family = AF_INET;
		memcpy((void *)&sin4->sin_addr.s_addr, cb->addr, 4);
		sin4->sin_port = cb->port;
	} else if (cb->addr_type == AF_INET6) {
        #if 0
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sin;
		sin6->sin6_family = AF_INET6;
		memcpy((void *)&sin6->sin6_addr, cb->addr, 16);
		sin6->sin6_port = cb->port;
		if (cb->ip6_ndev_name[0] != 0) {
			struct net_device *ndev;

			ndev = __dev_get_by_name(&init_net, cb->ip6_ndev_name);
			if (ndev != NULL) {
				sin6->sin6_scope_id = ndev->ifindex;
				dev_put(ndev);
			}
		}
        #endif
	}
}

static void krdma_run_server(struct krdma_cb *cb)
{
    printk("run server \n");
    //.crate pd, mr.cq ,wait for info from client
    struct sockaddr_storage sin;
    struct ib_device *ibdev;
    struct ib_pd *ibpd;
    struct ib_cq *ibcq;
    struct ib_mr *ibmr;
    struct ib_qp *ibqp;
    int ret;
    uint64_t *bufaddr;

    printk("get cb's info: \n");
    u32 ipaddr;
    ipaddr = cb->addr[3]| cb->addr[2]| cb->addr[1]| cb->addr[0];
    printk("addrstr: %s \n",cb->addr_str);
    printk("ipaddr: 0x%x \n",ipaddr);
    printk("port:   %d \n",cb->port);

    fill_sockaddr(&sin,cb);

    ret = rdma_bind_addr(cb->cm_id, (struct sockaddr *)&sin); //find ib_device & get src ip;
    if (ret) {
		printk("rdma_bind_addr error %d\n", ret);
		return ret;
	}
    DEBUG_LOG("rdma_bind_addr successful\n");

    if(!reg_supported(cb->cm_id->device))
            printk("not support\n");


    ibdev = cb->cm_id->device;

    //before socket, create some res.
    ibpd = ib_alloc_pd(ibdev,0);
    if(IS_ERR(ibpd)){
            printk("pd wrong\n");
            ret = PTR_ERR(ibpd);
            goto error0;
    }
    cb->pd = ibpd;

    struct ib_cq_init_attr cqattr;
    cqattr.cqe = 10;
    cqattr.flags = 0;
    cqattr.comp_vector = 1;

    ibcq = ib_create_cq(ibdev,NULL,NULL,NULL,&cqattr);
    if(IS_ERR(ibcq)){
            printk("cq wrong \n");
            ret = PTR_ERR(ibcq);
            goto error1;
    }
    cb->cq = ibcq;

    struct ib_qp_init_attr *qp_attr;
    qp_attr = kzalloc(sizeof(*qp_attr),GFP_KERNEL);
    qp_attr->send_cq = ibcq;
    qp_attr->recv_cq = ibcq;
    qp_attr->cap.max_send_wr = 10;
    qp_attr->cap.max_recv_wr = 10;
    qp_attr->cap.max_send_sge = 1;
    qp_attr->cap.max_recv_sge = 1;

    qp_attr->qp_type = IB_QPT_RC;

    ibqp = ib_create_qp(ibpd,qp_attr);
    if (IS_ERR(ibqp)) {
                printk("biqp wrong..\n");//added by hs
                ret = PTR_ERR(ibqp);
                goto error2;
    }
    cb->qp = ibqp;

    bufaddr             = kzalloc(16,GFP_KERNEL);
    cb->send_buf.buf    = bufaddr;
    cb->send_buf.size   = 16;
    cb->rdma_mr         = ibdev->ops.get_dma_mr(ibpd,IB_ACCESS_REMOTE_READ|IB_ACCESS_REMOTE_WRITE|IB_ACCESS_LOCAL_WRITE);
    if(IS_ERR(cb->rdma_mr)){
            printk("rdma mr wrong \n");
            ret = PTR_ERR(cb->rdma_mr);
            goto error3;
    }

    cb->rdma_mr->device     = ibpd->device;
    cb->rdma_mr->pd         = ibpd;
    cb->rdma_mr->uobject    = NULL;
    atomic_inc(&ibpd->usecnt);
    cb->rdma_mr->need_inval = false;
    cb->send_buf.rkey       = cb->rdma_mr->rkey; // get rkey

    cb->send_dma_addr       = ib_dma_map_single(ibdev,cb->send_buf.buf,cb->send_buf.size, DMA_BIDIRECTIONAL);
    if(ib_dma_mapping_error(ibdev,cb->send_dma_addr))
    {
            printk("mapping error \n");
            goto error4;
    }
    printk("create rs success end \n");
    printk("start to exchange info with client \n");
    //start_my_server();


    printk("start to modify qp \n");
    #if 0
    struct ib_qp_attr attr;
    attr.qp_state = IB_QPS_INIT;
    attr.pkey_index = 0x0;
//  attr.qkey = 0x0;
    attr.port_num = 1;
    attr.qp_access_flags =IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ |
                            IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_ATOMIC;
    int qp_attr_mask = IB_QP_STATE | IB_QP_PKEY_INDEX |IB_QP_PORT |IB_QP_ACCESS_FLAGS;
    #endif

error4:
    kfree(bufaddr);
error3:
    ib_dereg_mr(cb->rdma_mr);
error2:
    ib_destroy_qp(ibqp);
error1:
    ib_destroy_cq(ibcq);
error0:
    ib_dealloc_pd(ibpd);




    return ;
}


static void krdma_run_client(struct krdma_cb *cb)
{
    printk("run client \n");
    //.crate pd, mr.cq ,exchange with server
    struct sockaddr_storage sin;
    struct ib_device *ibdev;
    struct ib_pd *ibpd;
    struct ib_cq *ibcq;
    struct ib_mr *ibmr;
    struct ib_qp *ibqp;
    int ret;
    uint64_t *bufaddr;

    printk("get cb's info: \n");
    u32 ipaddr;
    ipaddr = cb->addr[3]| cb->addr[2]| cb->addr[1]| cb->addr[0];
    printk("addrstr: %s \n",cb->addr_str);
    printk("ipaddr: 0x%x \n",ipaddr);
    printk("port:   %d \n",cb->port);
    
    fill_sockaddr(&sin,cb);

    ret = rdma_bind_addr(cb->cm_id, (struct sockaddr *)&sin); //find ib_device & get src ip;
    if (ret) {
		printk("rdma_bind_addr error %d\n", ret);
		return ret;
	}
    DEBUG_LOG("rdma_bind_addr successful\n");

    if(!reg_supported(cb->cm_id->device))
            printk("not support\n");


    ibdev = cb->cm_id->device;

    ibpd = ib_alloc_pd(ibdev,0);
    if(IS_ERR(ibpd)){
            printk("pd wrong\n");
            ret = PTR_ERR(ibpd);
            goto error0;
    }
    cb->pd = ibpd;

    struct ib_cq_init_attr cqattr;
    cqattr.cqe = 10;
    cqattr.flags = 0;
    cqattr.comp_vector = 1;

    ibcq = ib_create_cq(ibdev,NULL,NULL,NULL,&cqattr);
    if(IS_ERR(ibcq)){
            printk("cq wrong \n");
            ret = PTR_ERR(ibcq);
            goto error1;
    }
    cb->cq = ibcq;

    struct ib_qp_init_attr *qp_attr;
    qp_attr = kzalloc(sizeof(*qp_attr),GFP_KERNEL);
    qp_attr->send_cq = ibcq;
    qp_attr->recv_cq = ibcq;
    qp_attr->cap.max_send_wr = 10;
    qp_attr->cap.max_recv_wr = 10;
    qp_attr->cap.max_send_sge = 1;
    qp_attr->cap.max_recv_sge = 1;

    qp_attr->qp_type = IB_QPT_RC;

    ibqp = ib_create_qp(ibpd,qp_attr);
    if (IS_ERR(ibqp)) {
                printk("biqp wrong..\n");//added by hs
                ret = PTR_ERR(ibqp);
                goto error2;
    }
    cb->qp = ibqp;

    bufaddr = kzalloc(16,GFP_KERNEL);
    cb->send_buf.buf = bufaddr;
    cb->send_buf.size = 16;
    cb->rdma_mr  = ibdev->ops.get_dma_mr(ibpd,IB_ACCESS_REMOTE_READ|IB_ACCESS_REMOTE_WRITE|IB_ACCESS_LOCAL_WRITE);
    if(IS_ERR(cb->rdma_mr)){
            printk("rdma mr wrong \n");
            ret = PTR_ERR(cb->rdma_mr);
            goto error3;
    }

    cb->rdma_mr->device     = ibpd->device;
    cb->rdma_mr->pd         = ibpd;
    cb->rdma_mr->uobject    = NULL;
    atomic_inc(&ibpd->usecnt);
    cb->rdma_mr->need_inval = false;
    cb->send_buf.rkey       = cb->rdma_mr->rkey; // get rkey

    cb->send_dma_addr       = ib_dma_map_single(ibdev,cb->send_buf.buf,cb->send_buf.size, DMA_BIDIRECTIONAL);
    if(ib_dma_mapping_error(ibdev,cb->send_dma_addr))
    {
            printk("mapping error \n");
            goto error4;
    }
    printk("create rs success end \n");

    printk("start to exchange info with server \n");
    //start_my_client();


    printk("start to modify qp \n");


error4:
    kfree(bufaddr);
error3:
    ib_dereg_mr(cb->rdma_mr);
error2:
    ib_destroy_qp(ibqp);
error1:
    ib_destroy_cq(ibcq);
error0:
    ib_dealloc_pd(ibpd);

    return ;

}

int krdma_doit(char *cmd)
{
    struct krdma_cb *cb;
    int op;
    int ret = 0;
    char *optarg;

    unsigned long optint;

    cb = kzalloc(sizeof(*cb), GFP_KERNEL);
    if(!cb)
        return -ENOMEM;
    
    mutex_lock(&krdma_mutex);
    list_add_tail(&cb->list,&krdma_cbs);
    mutex_unlock(&krdma_mutex);

    cb->server = -1;
    cb->state = IDLE;
    cb->size = 16; //data size
    cb->txdepth = 60;
    init_waitqueue_head(&cb->sem);

    while((op = krdma_getopt("krdma", &cmd, krdma_opts, NULL, &optarg, &optint)) != 0) {
        switch(op){
            case 'a':
                cb->addr_str = optarg;
                in4_pton(optarg, -1, cb->addr, -1 ,NULL);
                cb->addr_type = AF_INET;
                DEBUG_LOG("ipaddr %s \n",optarg);
                break;
             case 'A':
                DEBUG_LOG("test ipv6 next time, now not supported \n");
                ret = -EINVAL;break;
             case 'p':
                cb->port = htons(optint);
                DEBUG_LOG("port %d\n", (int)optint);
                break;
             case 'P':
                cb->poll = 1;
                DEBUG_LOG("server\n");break;
             case 's':
                 cb->server = 1;
                DEBUG_LOG("server\n");
                break;
             case 'S':
                 cb->size = optint;
                 if((cb->size < 1 || cb->size > 60)){
                     printk("Invalid size \n");
                     ret = EINVAL;
                 }else
                 {
                     DEBUG_LOG("size %d \n",(int)optint);
                 }
                 break;
             case 'C':
                 cb->count = optint;
                 if(cb->count < 0){
                     printk("invalid count \n");
                     ret = EINVAL;
                 }else
                 {
                     DEBUG_LOG("count %d\n", (int) cb->count);
                 }
                 break;
             case 'v':
                 cb->verbose++;
                 DEBUG_LOG("verbose\n");
                 break;
             case 'V':
                cb->validate++;
                DEBUG_LOG("validate data\n");
                break;
             case 'l':
                cb->wlat++;
                break;
             case 'L':
                cb->rlat++;
                break;
             case 'B':
                cb->bw++;
                break;
             case 'd':
                cb->duplex++;
                break;
             case 'I':
			    cb->server_invalidate = 1;
			    break;
             case 't':
			cb->tos = optint;
			DEBUG_LOG("type of service, tos=%d\n", (int) cb->tos);
			break;
             case 'T':
                cb->txdepth = optint;
                DEBUG_LOG("txdepth %d\n", (int) cb->txdepth);
                break;
             case 'Z':
                cb->local_dma_lkey = 1;
                DEBUG_LOG("using local dma lkey\n");
                break;
             case 'R':
                cb->read_inv = 1;
                DEBUG_LOG("using read-with-inv\n");
                break;
             case 'f':
                cb->frtest = 1;
                DEBUG_LOG("fast-reg test!\n");
                break;
             default:
                printk("unknown opt %s\n", optarg);
                ret = -EINVAL;
                break;       
                    }
            }
    if(ret)
        goto out;
    
    if (cb->server == -1) {
		printk("must be either client or server\n");
		ret = -EINVAL;
		goto out;
	}

    if ((cb->frtest + cb->bw + cb->rlat + cb->wlat) > 1) {
		printk("Pick only one test: fr, bw, rlat, wlat\n");
		ret = -EINVAL;
		goto out;
	}

    cb->cm_id = rdma_create_id(&init_net, NULL, cb, RDMA_PS_TCP, IB_QPT_RC);
    if (IS_ERR(cb->cm_id)) {
		ret = PTR_ERR(cb->cm_id);
		printk("rdma_create_id error %d\n", ret);
		goto out;
	}
    DEBUG_LOG("created cm_id %p\n", cb->cm_id); 


    if(cb->server)
            krdma_run_server(cb);
    else
    {
            krdma_run_client(cb);
    }

    DEBUG_LOG("destroy cm_id %p\n", cb->cm_id);
    rdma_destroy_id(cb->cm_id);
    out:
    mutex_lock(&krdma_mutex);
    list_del(&cb->list);
    mutex_unlock(&krdma_mutex);
    kfree(cb);
    return ret;
    
}




static ssize_t krdma_write_proc(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
    char *cmd;
    int rc;

    if(!try_module_get(THIS_MODULE))
            return -ENODEV;
    cmd = kmalloc(count, GFP_KERNEL);
    if(cmd == NULL){
            printk("kmalloc failure\n");
            return -ENOMEM;
    }
    if(copy_from_user(cmd, buffer, count)) {
            kfree(cmd);
            return -EFAULT;
    }

    cmd[count -1] = 0;
    DEBUG_LOG("proc write %s\n",cmd);

    rc = krdma_doit(cmd);
    kfree(cmd);
    module_put(THIS_MODULE);
    if(rc)
            return rc;
    else
    {
           return (int) count;
    }
    

}




static int krdma_read_proc(struct seq_file *seq, void *v)
{
        struct krdma_cb *cb;
        int num = 1;

        if(!try_module_get(THIS_MODULE))
                return -ENODEV;
        
        DEBUG_LOG("proc read called ...\n");
        mutex_lock(&krdma_mutex);
        list_for_each_entry(cb, &krdma_cbs, list){
            if (cb->pd) {
                seq_printf(seq,
			     "%d-%s %lld %lld %lld %lld %lld %lld %lld %lld\n",
			     num++, cb->pd->device->name, cb->stats.send_bytes,
			     cb->stats.send_msgs, cb->stats.recv_bytes,
			     cb->stats.recv_msgs, cb->stats.write_bytes,
			     cb->stats.write_msgs,
			     cb->stats.read_bytes,
			     cb->stats.read_msgs);
            }else
            {
                seq_printf(seq, "%d listen\n", num++);
            }
            
        }

        mutex_unlock(&krdma_mutex);
        module_put(THIS_MODULE);
        return 0;
}


static int krdma_open(struct inode *inode, struct file *file)
{
        return single_open(file, krdma_read_proc, inode->i_private);
}


static struct file_operations krdma_ops = {
    .owner      = THIS_MODULE,
    .open       = krdma_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release,
    .write      = krdma_write_proc
};

static int __init krdma_init(void)
{
    DEBUG_LOG(" krdma init start\n");
    krdma_proc = proc_create("krdma", 0666, NULL, &krdma_ops);
    if(krdma_proc == NULL) {
        printk("cannot create /proc/krdma \n");
        return -ENOMEM;
    }
    return 0;
}

static void __exit krdma_exit(void)
{
    DEBUG_LOG("krdma_exit \n");
    remove_proc_entry("krdma", NULL);
}

module_init(krdma_init);
module_exit(krdma_exit);