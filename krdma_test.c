#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
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
        uint64_t buf;
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
        struct ib_mr *rdma_mr;

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


        struct list_head list;

};



static void krdma_run_server(struct krdma_cb *cb)
{
    printk("run server \n");
}


static void krdma_run_client(struct krdma_cb *cb)
{
    printk("run client \n");
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
                printk(KERN_ERR PFX "unknown opt %s\n", optarg);
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

    if(cb->server)
            krdma_run_server(cb);
    else
    {
            krdma_run_client(cb);
    }

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