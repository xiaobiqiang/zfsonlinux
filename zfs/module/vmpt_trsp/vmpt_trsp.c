#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/in.h>  
#include <linux/inet.h>  
#include <linux/net.h>
#include <linux/socket.h>  
#include <net/sock.h>
#include <net/af_rxrpc.h>
#include <linux/miscdevice.h>
#include <sys/cluster_san.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/blkdev.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/aer.h>
#include <linux/gfp.h>
#include <asm/device.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <sys/zfs_context.h>
#include <linux/string.h>
#include <sys/nvpair.h>
#include <linux/types.h>
#include <linux/completion.h>
#include <linux/wait.h>
#include <sys/modhash.h>
#include <sys/file.h>
#include <net/tcp.h>
#include <sys/commsock.h>
#include <linux/mutex.h>
#include <sys/kmem_cache.h>

#define CS_MAGIC            0x12345678
#define CS_HASH_TYPE_ID     0
#define CS_HASH_TYPE_PTR    1
#define CS_HASH_TYPE_STR    2

#define CS_MIN_SZ_SHIFT     9  
#define CS_MIN_SZ           (1<<CS_MIN_SZ_SHIFT)   /* 512byte */
#define CS_MAX_SZ_SHIFT     17 
#define CS_MAX_SZ           (1<<CS_MAX_SZ_SHIFT)   /* 128K */
#define CS_CACHE_NUM        

#define CSK_DATA_MIN_SHIFT  12
#define CSK_DATA_MAX_SHIFT  17
#define CSK_DATA_MIN        (1<<CSK_DATA_MIN_SHIFT)
#define CSK_DATA_MAX        (1<<CSK_DATA_MAX_SHIFT)
#define CSK_MEMPOOL_NUM      (CSK_DATA_MAX>>CSK_DATA_MIN_SHIFT+1)

#define SET_ERROR(err)  ((err) > 0 ? -err : err)

typedef enum commsock_wt_code {
	CS_WT_CODE_SELFUP = 0x00,
	CS_WT_CODE_ACCEPT = 0x01,
	CS_WT_CODE_EOF
} commsock_wt_code_e;

typedef struct commsock_ioc {
    commsock_ioc_cmd_e cmd;
    int (*hdl)(nvlist_t *, nvlist_t **);
} commsock_ioc_t;

typedef struct commsock_tq {
    taskq_t **ct_tqpptr;
    char    *ct_name;
    int     ct_pri;
    int     ct_nthr;
    int     ct_minalloc;
    int     ct_maxalloc;
    int     ct_flag;
    int     ct_state;
} commsock_tq_t;

typedef struct commsock_wt {
	commsock_wt_code_e	cw_type;
	struct completion 	*cw_comp;
} commsock_wt_t;

typedef struct commsock_mod_hash {
    uint_t      cmp_type;
    mod_hash_t  **cmp_ptrhash;
    char        *cmp_name;
    size_t      cmp_nchain;
    void        (*cmp_val_dtor)(mod_hash_val_t);
    size_t      cmp_key_elem_size;
} commsock_mod_hash_t;

typedef struct commsock_msg_header {
	uint_t cm_magic;
	uint_t cm_type;
	size_t cm_dlen;
	size_t cm_hdsz;
} commsock_msg_header_t;

typedef struct commsock_rx_cb {
	uint_t	crc_type;
	void 	(*crc_rx_cb)(void *);
	void 	*crc_arg;
} commsock_rx_cb_t;

typedef struct commsock_cs_rx_cb_arg {
    nvlist_t        *csrc_nvl;
    cs_rx_data_t    *csrc_cs_data;
    void            *csrc_arg;
} commsock_cs_rx_cb_arg_t;

typedef struct commsock_snd_msg {
    struct msghdr *css_mhdr;
    struct kvec   *css_vec;
} commsock_snd_msg_t;

typedef struct commsock_snd_page {
    struct page *pg;
    size_t offset;
    size_t len;
} commsock_snd_page_t;

typedef struct commsock_snd {
    union {
        commsock_snd_msg_t msg;
        commsock_snd_page_t page;
    } snd;
#define smsg        snd.msg
#define spg         snd.page
#define smsg_hdr    snd.msg.css_mhdr
#define smsg_vec    snd.msg.css_vec
#define spg_page    snd.page.pg
#define spg_off     snd.page.offset
#define spg_len     snd.page.len

    boolean_t      css_is_page;
    size_t         css_len; /* all len */
    boolean_t      css_flag;
    size_t         css_cnt; /* please always 1 */
} commsock_snd_t;

typedef struct commsock_rcv_arg {
    commsock_lnk_t *lnk;
    struct socket *sock;
} commsock_rcv_arg_t;

typedef struct commsock_accpt_arg {
    struct socket *sock;
    int idx;
} commsock_accpt_arg_t;

typedef struct commsock_stat {
    commsock_conf_t cs_loc_host;
	struct socket	*cs_socket[CS_HOST_MAX_LINK];
	
    kmutex_t    	cs_gbmutex;

    mod_hash_t      *cs_lnk_snd;
    mod_hash_t      *cs_lnk_rcv;
	mod_hash_t		*cs_rx_cb;
	mod_hash_t      *cs_hosts;
	
	/* notify completion var */
	struct completion cs_selfup_cmp; 
	struct completion cs_accpt_cmp; 

    
	struct task_struct *cs_thr_accept[CS_HOST_MAX_LINK];

	taskq_t *rcv_tq;
	struct workqueue_struct *xprt_wq;
	struct socket *sock;
	struct task_struct *accpt_wkt;

	struct kmem_cache *rcv_mm_cache;
	mempool_t *rcv_mm_pool;
	struct kmem_cache *rcv_hd_cache;
	mempool_t *rcv_hd_pool;
	
    /* accept peer */
    taskq_t   *cs_tq_accpt;
    /* recv data */
    taskq_t   *cs_tq_recv;
    /* send data */
    taskq_t   *cs_tq_send;
    /* recv ctrl msg */
    taskq_t   *cs_tq_comm;
    /* hdl ctrl msg */
    taskq_t   *cs_tq_hdl;
} commsock_stat_t;

static boolean_t
commsock_check_attrs(commsock_conf_t *);
static int
commsock_stat_init_socket(struct socket **);
static void
commsock_stat_release_socket(struct socket **sock);
static int
commsock_connect_host(commsock_conf_t *attr);
static void
commsock_lnk_hash_valdtor(mod_hash_val_t val);
static void
commsock_hosts_hash_valdtor(mod_hash_val_t val);
static void
commsock_rx_cb_hash_valdtor(mod_hash_val_t val);
static long 
commsock_unlocked_ioctl(struct file *, unsigned int, unsigned long);
static int 
commsock_open(struct inode *, struct file *);
static int
commsock_release(struct inode *, struct file *);
static int
commsock_ioc_set_tcp(nvlist_t *, nvlist_t **);
static int
commsock_ioc_get_tcp(nvlist_t *, nvlist_t **);

static commsock_stat_t cs_stat;

/* elements must be allocated by kmem_(z)alloc */
static commsock_mod_hash_t cs_hash_vec[] = {
    {CS_HASH_TYPE_ID, &cs_stat.cs_lnk_snd, "cs_lnk_snd", CS_MAX_HOSTS, commsock_lnk_hash_valdtor, 0},
    {CS_HASH_TYPE_ID, &cs_stat.cs_lnk_rcv, "cs_lnk_rcv", CS_MAX_HOSTS, commsock_lnk_hash_valdtor, 0},
    {CS_HASH_TYPE_ID, &cs_stat.cs_rx_cb, "cs_rx_cb", CS_MAX_HOSTS, commsock_rx_cb_hash_valdtor, 0},
    {CS_HASH_TYPE_STR, &cs_stat.cs_hosts, "cs_hosts", CS_MAX_HOSTS, commsock_hosts_hash_valdtor, 0},
};

static commsock_tq_t cs_taskq_vec[] = {
    {&cs_stat.cs_tq_comm, "cs_tq_comm", minclsyspri, 1, 8, INT_MAX, TASKQ_PREPOPULATE},
    {&cs_stat.cs_tq_hdl, "cs_tq_hdl", minclsyspri, 16, 8, INT_MAX, TASKQ_PREPOPULATE},
    {&cs_stat.cs_tq_accpt, "cs_tq_accpt", minclsyspri, 1, 8, INT_MAX, TASKQ_PREPOPULATE},
    {&cs_stat.cs_tq_send, "cs_tq_send", minclsyspri, 1, 8, INT_MAX, TASKQ_PREPOPULATE},
    {&cs_stat.cs_tq_recv, "cs_tq_recv", minclsyspri, 1, 8, INT_MAX, TASKQ_PREPOPULATE}
};

static commsock_wt_t cs_wt_vec[] = {
	{CS_WT_CODE_SELFUP,     &cs_stat.cs_selfup_cmp},
	{CS_WT_CODE_ACCEPT,    &cs_stat.cs_accpt_cmp}
};

static commsock_ioc_t cs_ioc_vec[] = {
    {COMMSOCK_IOC_FIRST,    NULL},
    {COMMSOCK_IOC_SET_TCP,  commsock_ioc_set_tcp},
    {COMMSOCK_IOC_GET_TCP,  commsock_ioc_get_tcp},
    {COMMSOCK_IOC_EOF,      NULL}
};

static const struct file_operations commsock_fops = {
	.owner		    = THIS_MODULE,
	.unlocked_ioctl	= commsock_unlocked_ioctl,
	.open		    = commsock_open,
	.release        = commsock_release
};

static struct miscdevice commsock_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name   = "commsock_dev",
	.fops   = &commsock_fops,
};

static void
commsock_lnk_hash_valdtor(mod_hash_val_t val)
{
    int i;
    commsock_lnk_t *lnk = val;
    
    for(i = 0; i < CS_HOST_MAX_LINK; i++) {
        if(lnk->cl_lnk_sck[i])
            sock_release(lnk->cl_lnk_sck[i]);
    }
    kfree(lnk);
}

static void
commsock_hosts_hash_valdtor(mod_hash_val_t val)
{
    commsock_conf_t *attr = val;
    kmem_free(attr, sizeof(*attr));
}

static void
commsock_rx_cb_hash_valdtor(mod_hash_val_t val)
{
    commsock_rx_cb_t *arg = val;
    if(arg)
        kmem_free(arg, sizeof(*arg));
}


static int
commsock_get_nvlist(uint64_t nvl, uint64_t size, nvlist_t **nvp)
{
	char *packed = NULL;
	int error = 0;
	nvlist_t *list = NULL;
        
	printk(KERN_ERR "%s:nvl:%llu", __func__, nvl);
	packed = kmem_alloc(size, KM_SLEEP);
	error = ddi_copyin((void *)(uintptr_t)nvl, packed, size, 0);
	printk(KERN_ERR "%s:ddi_copyin_err:%d", __func__, error);
	if(error != 0)
		goto out;
	error = nvlist_unpack(packed, size, &list, KM_SLEEP);
	printk(KERN_ERR "%s:nvlist_unpack_err:%d", __func__, error);
out:
	kmem_free(packed, size);
	*nvp = list;
	return error;
}

static int
commsock_put_nvlist(commsock_cmd_t *cc, nvlist_t *nvl)
{
	char *packed = NULL;
	int error = 0;
	size_t size = 0;

	if(nvlist_pack(nvl, &packed, &size, NV_ENCODE_XDR, KM_SLEEP) != 0) {
        printk(KERN_ERR "%s:nvlist_pack failed", __func__);
        goto out;
	}
	if(size > cc->cc_nvlist_dst_size) {
        cc->cc_nvlist_dst_size = size;
        error = SET_ERROR(ENOMEM);
        goto out;
	}
	error = ddi_copyout(packed, 
	    (void *)(uintptr_t)cc->cc_nvlist_dst, size, 0);
out:
	cc->cc_nvlist_dst_size = ((error != 0) ? 0 : size);
	if(packed)
	    kmem_free(packed, size);
	return error;
}

static long 
commsock_unlocked_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
    int error;
    int flag = 0;
    int size = sizeof(commsock_cmd_t);
    commsock_cmd_t *cc_arg = NULL;
    int (*hdl)(nvlist_t *, nvlist_t **);
    nvlist_t *innvl = NULL;
    nvlist_t *outnvl = NULL;

    printk(KERN_ERR "%s:cmd:%u", __func__, cmd);
    if( (cmd<=COMMSOCK_IOC_FIRST) || 
        (cmd>=COMMSOCK_IOC_EOF) ||
        ((hdl = cs_ioc_vec[cmd].hdl) == NULL) ) {
        error = SET_ERROR(EINVAL);
        goto out;
    }

    cc_arg = kmalloc(size, KM_SLEEP);
    error = ddi_copyin((void *)arg, cc_arg, size, flag);
    if (error != 0) {
        error = SET_ERROR(EFAULT);
        goto free_arg;
    }
    printk(KERN_ERR "%s:cc_nvlist_src_size:%llu", __func__, cc_arg->cc_nvlist_src_size);    
    if (cc_arg->cc_nvlist_src_size != 0) {
        error = commsock_get_nvlist(cc_arg->cc_nvlist_src, 
            cc_arg->cc_nvlist_src_size, &innvl);
        if (error != 0) {
            error = SET_ERROR(EFAULT);
            goto free_arg;
        }
    }
    printk(KERN_ERR "%s:going into hdl", __func__);    
    error = hdl(innvl, &outnvl);
    if(error != 0) {
        goto free_nvl;
    }
    
    if(outnvl) {
        (void)commsock_put_nvlist(cc_arg, outnvl);
    }

    error = ddi_copyout(cc_arg, (void *)(uintptr_t)arg, size, 0);
    if(error != 0)
        error = SET_ERROR(EFAULT);
free_nvl:
    if(outnvl)
        nvlist_free(outnvl);
    if(innvl)
        nvlist_free(innvl);
free_arg:
    kfree(cc_arg);
out:
    return error;
}

static int 
commsock_open(struct inode *dp, struct file *fp)
{
    return 0;
}

static int
commsock_release(struct inode *dp, struct file *fp)
{
    return 0;
}

/* don't check parameters if valid */
static int
commsock_ioc_set_tcp(nvlist_t *conf, nvlist_t **outnvl)
{
    int error = 0;
    char *ipaddr;
    int port;
    
    if(commsock_check_attrs(&cs_stat.cs_loc_host)) {
        printk(KERN_ERR "%s: already config", __func__);
        error = SET_ERROR(EEXIST);
        goto out;
    }

    if( (nvlist_lookup_string(conf, CS_ATTR_IPADDR, &ipaddr) != 0) ||
        (nvlist_lookup_int32(conf, CS_ATTR_PORT, &port) != 0) ) {
        printk(KERN_ERR "%s: invalid config nvlist", __func__);
        error = SET_ERROR(EINVAL);
        goto out;
    }

    printk(KERN_INFO "%s:attr set to ipaddr:%s,port:%d",
        __func__, ipaddr, port);
    mutex_enter(&cs_stat.cs_gbmutex);
    cs_stat.cs_loc_host.cc_port = port;
    cs_stat.cs_loc_host.cc_hostid = zone_get_hostid(NULL);
    strncpy(cs_stat.cs_loc_host.cc_ipaddr, ipaddr, strlen(ipaddr)+1);
    mutex_exit(&cs_stat.cs_gbmutex);
out:
    return error;
}

static int
commsock_ioc_get_tcp(nvlist_t *conf, nvlist_t **outnvl)
{
    int error;
    nvlist_t *nvl = NULL;
    char *ipaddr;
    int hostid;
    int port;
    
    if(!commsock_check_attrs(&cs_stat.cs_loc_host)) {
        printk(KERN_ERR "%s: invalid attrs", __func__);
        error = SET_ERROR(EINVAL);
        goto error;
    }

    if(nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP) != 0) {
        error = SET_ERROR(ENOMEM);
        goto error;
    }

    ipaddr = cs_stat.cs_loc_host.cc_ipaddr;
    hostid = cs_stat.cs_loc_host.cc_hostid;
    port= cs_stat.cs_loc_host.cc_port;
    if( (nvlist_add_int32(nvl, CS_ATTR_HOSTID, hostid) != 0) ||
        (nvlist_add_string(nvl, CS_ATTR_IPADDR, ipaddr) != 0) ||
        (nvlist_add_int32(nvl, CS_ATTR_PORT, port) != 0) ) {
        printk(KERN_ERR "%s: nvlist add attrs failed", __func__);
        error = SET_ERROR(EFAULT);
        goto free_nvl;
    }

    if(outnvl != NULL)
        *outnvl = nvl;
    return 0;
free_nvl:
    nvlist_free(nvl);
error:
    return error;
}

static boolean_t
commsock_check_attrs(commsock_conf_t *attr)
{
    boolean_t valid = B_FALSE;
    char *ipaddr = attr->cc_ipaddr;
    int port = attr->cc_port;

    if((port<=0) || (port>=65536))
        return valid;
    if(ipaddr[0] == '\0')
        return valid;
    return B_TRUE;
}

static int
inet_pton(const char *src, u_char *dst)
{
     static const char digits[] = "0123456789";
     int saw_digit, octets, ch;
#define NS_INADDRSZ     4
     u_char tmp[NS_INADDRSZ], *tp;

     saw_digit = 0;
     octets = 0;
     *(tp = tmp) = 0;
     while ((ch = *src++) != '\0') {
             const char *pch;

             if ((pch = strchr(digits, ch)) != NULL) {
                     u_int new = *tp * 10 + (pch - digits);

                     if (saw_digit && *tp == 0)
                             return (0);
                     if (new > 255)
                             return (0);
                     *tp = new;
                     if (!saw_digit) {
                            if (++octets > 4)
                                    return (0);
                            saw_digit = 1;
                    }
            } else if (ch == '.' && saw_digit) {
                    if (octets == 4)
                            return (0);
                    *++tp = 0;
                    saw_digit = 0;
            } else
                    return (0);
    }
    if (octets < 4)
            return (0);
    memcpy(dst, tmp, NS_INADDRSZ);
    return (1);
}

int 
commsock_register_rx_cb(uint_t type, void (*fn)(commsock_rx_cb_arg_t *), void *arg)
{
	int error;
	commsock_rx_cb_t *rx = kmem_zalloc(sizeof(commsock_rx_cb_t), KM_SLEEP);
	rx->crc_type = type;
	rx->crc_arg = arg;
	rx->crc_rx_cb = fn;

	if((error=mod_hash_insert(cs_stat.cs_rx_cb, type, rx)) != 0)
		goto free_rx;
	return 0;
free_rx:
	kmem_free(rx, sizeof(*rx));
	return error;
}

/* return arg */
void *
commsock_deregister_rx_cb(uint_t type)
{
    int err;
    void *arg;
    commsock_rx_cb_t *rx; 

    err = mod_hash_remove(cs_stat.cs_rx_cb, (mod_hash_key_t)type, &rx);
    if(err)
        return NULL;
    arg = rx->crc_arg;
    kmem_free(rx, sizeof(*rx));
    return arg;
}

static void
commsock_notify_finish(uint_t wt_code)
{
	if(wt_code >= CS_WT_CODE_EOF)
	    return ;
	complete(cs_wt_vec[wt_code].cw_comp);
}

static void 
commsock_wait_for_finish(uint_t wt_code)
{
	if(wt_code >= CS_WT_CODE_EOF)
	    return ;
	wait_for_completion(cs_wt_vec[wt_code].cw_comp);
}

/* 
 * 0 if timedout
 * otherwise return remained time.
 */
static int
commsock_timedwait_for_finish(uint_t wt_code, unsigned long tmout)
{
	unsigned long tm;
	struct completion *comp;
	
	if(wt_code >= CS_WT_CODE_EOF)
	    return -1;
	comp = cs_wt_vec[wt_code].cw_comp;
	return wait_for_completion_timeout(comp, tmout);
}

static void
commsock_free_cs_rx_cb_arg(commsock_cs_rx_cb_arg_t *arg)
{
    if(arg->csrc_nvl)
        nvlist_free(arg->csrc_nvl);
    if(arg->csrc_cs_data)
        csh_rx_data_free_ext(arg->csrc_cs_data);
    kmem_free(arg, sizeof(*arg));
}

void 
commsock_free_rx_cb_arg(commsock_rx_cb_arg_t *arg)
{
    cs_kmem_free(arg->cd_data, arg->cd_dlen);
    cs_kmem_free(arg->cd_head, arg->cd_hlen);
    kmem_cache_free(cs_stat.cs_rx_data_cache, arg);
}

/* ctrl msg send entry */
static int 
commsock_cs_send_msg(void *sess, void *msg, size_t len)
{
    int ret = 0;
	if (sess == CS_BRDCAST_SESSION) {
		cluster_san_broadcast_send(NULL, 0, msg, len, 
		    CLUSTER_SAN_MSGTYPE_COMMSOCK, 0);
	} else {
		ret = cluster_san_host_send(sess, NULL, 0, msg, len,
		    CLUSTER_SAN_MSGTYPE_COMMSOCK, 0, 1, 3);	
	}
	return (ret);
}

/*
static int
commsock_host_send_msg_impl(
    struct socket *sock, struct msghdr *hdr,
    struct kvec *vec, size_t num, size_t size)
{
    int ret;
    ret = kernel_sendmsg(sock, hdr, vec, num, size);
    if(ret == -EAGAIN)
        ret = 0;
    return ret;
}

static int
commsock_host_send_page_impl(
    struct socket *sock, struct page *page, 
    int offset, size_t size, int flags)
{
    int ret;
    ret = kernel_sendpage(sock, page, offset, size, flags);
    if(ret == -EAGAIN)
        ret = 0;
    return ret;
}


static ssize_t
commsock_host_send_entire(commsock_lnk_t *sess, commsock_snd_t *snd)
{
    int ret;
    size_t totlen = 0;
    size_t snd_len = 0;
    int flag = 0;
    struct socket *sock = sess->cl_lnk_sck;
    
    totlen = snd->css_len;
    VERIFY(snd->css_cnt == 1);
    
    while(1) {
        if(snd->css_is_page) {
            ret = commsock_host_send_page_impl(sock, snd->spg_page, 
                snd->spg_off+snd_len, snd->spg_len-snd_len, 
                snd->css_flag);
            if(ret < 0)
                break;
            else if((snd_len += ret) < totlen)
                continue;
            ret = snd_len;
            break;
        } else {
            snd->smsg_hdr->msg_flags = snd->css_flag;
            ret = commsock_host_send_msg_impl(sock, snd->smsg_hdr, 
                snd->smsg_vec, snd->css_cnt,snd->css_len);
            if(ret < 0)
                break;
            else if((snd_len += ret) < totlen) {
                snd->css_len = totlen-snd_len;
                snd->smsg_vec->iov_base += ret;
                snd->smsg_vec->iov_len -= ret;
                continue;
            }
            ret = snd_len;
            break;
        }
    }
    return ret;
}
*/

static struct socket *
commsock_get_next_sndsck(commsock_lnk_t *lnk)
{
    struct socket *sock = NULL;
    spin_lock(&lnk->cl_spinlock);
    sock = lnk->cl_lnk_sck[lnk->cl_next_idx++];
    if(lnk->cl_next_idx >= lnk->cl_lnk_cnt)
        lnk->cl_next_idx = 0;
    spin_unlock(&lnk->cl_spinlock);
    return sock;
}


int commsock_host_send_msg(void *sess, uint_t type, 
    void *header, size_t hdsz, 
    struct kvec *data, size_t cnt, size_t dlen)
{
    int i = 0,error = 0;
    size_t hd_cnt = ((header && hdsz) ? 1 : 0);
    size_t vec_cnt = 1+hd_cnt+cnt;
    size_t totlen = sizeof(commsock_msg_header_t)+hdsz+dlen;
    struct msghdr mhdr;
    struct kvec *vecp = NULL;
    struct kvec *vecp_org = NULL;
    commsock_msg_header_t mheader = {CS_MAGIC,type,dlen,hdsz};
    commsock_lnk_t *lnk = sess;
    struct socket *sock = NULL;
    
    if(!header && (!cnt || !dlen) ) {
        error = SET_ERROR(EINVAL);
        goto out;
    }

    vecp_org = vecp = kmalloc(sizeof(*vecp)*vec_cnt, GFP_KERNEL);
    
    vecp->iov_base = &mheader;
    vecp->iov_len = sizeof(mheader);
    vecp++;
    
    if(hd_cnt) {
        vecp->iov_base = header;
        vecp->iov_len = hdsz;
        vecp++;
    } 

    if(data && cnt)
        memcpy(vecp, data, sizeof(*vecp)*cnt);
    
    bzero(&mhdr, sizeof(mhdr));
    error = kernel_sendmsg(
        sock, &mhdr, vecp_org, vec_cnt, totlen);
    if(error > 0)
        error -= sizeof(mheader);
    else if(error == -EAGAIN)
        error = 0;
    kfree(vecp_org);
out:
    return error;
}

static uint_t
commsock_broadcast_hash_walk_cb(
    mod_hash_key_t key, mod_hash_val_t *valp, void *priv)
{
    int ret;
    commsock_snd_t *snd = priv;
    uint_t type = snd->css_cnt;
    commsock_lnk_t *lnk = (commsock_lnk_t *)valp;
    cmn_err(CE_NOTE, "%s:lnk->cl_hash_key:%p", __func__, lnk->cl_hash_key);
    ret = commsock_host_send_msg(lnk, type, snd->smsg_vec->iov_base,
        snd->smsg_vec->iov_len, NULL, 0, 0);
    printk(KERN_WARNING "%s: key:%d, ret:%d", __func__, (int)key, ret);
    return MH_WALK_CONTINUE;
}

void
commsock_broadcast_msg(uint_t type, void *header, size_t hdsz) 
{
    int ret;
    struct kvec vec;
    commsock_snd_t snd = {
        .css_cnt = type,
        .smsg_vec = &vec,
    };
    
    vec.iov_base = header;
    vec.iov_len = hdsz;
    mod_hash_walk(cs_stat.cs_lnk_snd, 
        commsock_broadcast_hash_walk_cb, &snd);
}

static int
commsock_brdcast_selfup(void)
{
    int error = 0;
    int cmd = CS_MSG_SELFUP;
    nvlist_t *nvlp = NULL;
    char *packed = NULL;
    size_t packlen = 0;
    
    if(!commsock_check_attrs(&cs_stat.cs_loc_host)) {
        printk(KERN_ERR "%s:invalid attrs", __func__);
        error = SET_ERROR(EINVAL);
        goto out;
    }

    if((error=commsock_ioc_get_tcp(NULL, &nvlp)) != 0) {
        printk(KERN_ERR "%s:commsock_ioc_get_tcp failed,error:%d", 
            __func__, error);
        goto out;
    }

    if(nvlist_add_int32(nvlp, "cmd", cmd) != 0) {
        printk(KERN_ERR "%s:nvlist_add_int32 failed", __func__);
        goto free_nvl;
    }
    
    if(nvlist_pack(nvlp, &packed, &packlen, NV_ENCODE_XDR, KM_SLEEP) != 0) {
        printk(KERN_ERR "%s:nvlist_pack failed", __func__);
        goto free_nvl;
    }

    (void)commsock_cs_send_msg(CS_BRDCAST_SESSION, packed, packlen);
    //commsock_wait_for_finish(CS_WT_CODE_SELFUP);
	kmem_free(packed, packlen);
free_nvl:
    nvlist_free(nvlp);
out:
    return error;
}

static int 
commsock_send_addhost(void *session)
{
    int error;
    int cmd = CS_MSG_ADD_INFO;
    nvlist_t *nvl = NULL;
    char *packed = NULL;
    size_t packlen = 0;
    
    error = commsock_ioc_get_tcp(NULL, &nvl);
    if(error != 0) {
        printk(KERN_ERR "%s:commsock_ioc_get_tcp failed", __func__);
        goto out;
    }

    if((error=nvlist_add_int32(nvl, "cmd", cmd)) != 0) {
        printk(KERN_ERR "%s:nvlist_add_int32 failed,error:%d", 
            __func__, error);
        goto out;
    }
    
    if((error=nvlist_pack(nvl, &packed, &packlen, NV_ENCODE_XDR, KM_SLEEP)) != 0) {
        printk(KERN_ERR "%s:nvlist_pack failed,error:%d", 
            __func__, error);
        goto out;
    }
    
    error = commsock_cs_send_msg(session, packed, packlen);
out:
    if(nvl)
        nvlist_free(nvl);
    if(packed)
        kmem_free(packed, packlen);
    return error;
}

static commsock_conf_t *
commsock_add_host(nvlist_t *nvl)
{
    int error = -1;
    commsock_conf_t *conf;
    char *ipaddr = NULL;
    
    conf = kmem_zalloc(sizeof(*conf), KM_SLEEP);
    if( !conf || ((error=nvlist_lookup_string(nvl, CS_ATTR_IPADDR, &ipaddr)) != 0) ||
        ((error=nvlist_lookup_int32(nvl, CS_ATTR_PORT, &conf->cc_port)) != 0) ||
        ((error=nvlist_lookup_int32(nvl, CS_ATTR_HOSTID, &conf->cc_hostid)) != 0) ) {
        printk(KERN_ERR "%s: nvlist_lookup failed,error:%d", __func__, error);
        goto free_conf;
    }    
    strncpy(conf->cc_ipaddr, ipaddr, strlen(ipaddr));
    printk(KERN_ERR "%s:cs_host:%p,hostid:%d,error:%d", __func__, 
        cs_stat.cs_hosts, conf->cc_hostid, error);

    error = mod_hash_insert(cs_stat.cs_hosts, 
        (mod_hash_key_t)(conf->cc_ipaddr), 
        (mod_hash_val_t)conf);
    if(error != 0) {
        if(error == MH_ERR_DUPLICATE) { 
            printk(KERN_ERR "%s:has same key:%d", __func__, conf->cc_hostid);
            error = SET_ERROR(EEXIST);
        } else {
            printk(KERN_ERR "%s:unknown error[%d] to insert host[%d]", 
                __func__, error, conf->cc_hostid);
        }
        goto free_conf;
    }
    printk(KERN_ERR "%s:add_host succeed,hostid:%d,ipaddr:%s", 
        __func__, conf->cc_hostid, conf->cc_ipaddr);
    return conf;
free_conf:
    if(conf)
        kmem_free(conf, sizeof(*conf));
    return NULL;
}

static int
commsock_remove_host(int hostid)
{
    return 0;
}

static void
commsock_hdl_msg_selfup(commsock_cs_rx_cb_arg_t *csrc)
{
    int error;
    commsock_conf_t *attr = NULL;
    nvlist_t *nvl = csrc->csrc_nvl;
    cs_rx_data_t *cs_data = csrc->csrc_cs_data;
    void *session = cs_data->cs_private;
    
    printk(KERN_ERR "%s:----------", __func__);
    attr = commsock_add_host(nvl);
    if(attr == NULL) {
        printk(KERN_ERR "%s:commsock_add_host failed", __func__);
        goto out;
    }

    error = commsock_send_addhost(session);
    if(error != 0) {
        printk(KERN_ERR "%s:commsock_send_addhost failed", __func__);
        goto del_host;
    }

    error = commsock_connect_host(attr);
    if(error != 0) {
        printk(KERN_ERR "%s:commsock_connect_host failed,hostid:%d", 
            __func__, attr->cc_hostid);
        goto del_host;
    }

    printk(KERN_INFO "%s:connect to %s successfully", 
        __func__, attr->cc_ipaddr);
    goto out;
    
del_host:
    commsock_remove_host(attr->cc_hostid);
out:
    commsock_free_cs_rx_cb_arg(csrc);
    return ;
}

static void
commsock_hdl_msg_addinfo(commsock_cs_rx_cb_arg_t *csrc)
{
    int error;
    commsock_conf_t *attr = NULL;
    nvlist_t *nvl = csrc->csrc_nvl;
    struct socket *newsock = NULL;
    
    attr = commsock_add_host(nvl);
    if(attr == NULL) {
        printk(KERN_ERR "%s:commsock_add_host failed", __func__);
        error = SET_ERROR(EFAULT);
        goto out;
    }

    error = commsock_connect_host(attr);
    if(error != 0) {
        printk(KERN_ERR "%s:commsock_connect_host failed,hostid:%d", 
            __func__, attr->cc_hostid);
        goto del_host;
    }
    
    printk(KERN_INFO "%s:connect to %s successfully", 
        __func__, attr->cc_ipaddr);
    goto out;
    
del_host:
    commsock_remove_host(attr->cc_hostid);
out:
    commsock_free_cs_rx_cb_arg(csrc);
    return ;
}

static void 
commsock_cs_rx_cb(cs_rx_data_t *cs_data, void *arg)
{
	int error;
	size_t dlen = cs_data->ex_len;
    void *packed = cs_data->ex_head;
	nvlist_t *nvl = NULL;
	int cmd = 0;
	commsock_cs_rx_cb_arg_t *csrc;
	printk(KERN_ERR "%s:data:%p,data_len:%u", 
		__func__, cs_data->ex_head, cs_data->ex_len);	

	if(nvlist_unpack(packed, dlen, &nvl, KM_SLEEP) != 0) {
		printk(KERN_ERR "%s:nvlist_unpack failed", __func__);
		goto free_cs;
	}
	if((error=nvlist_lookup_int32(nvl, "cmd", &cmd)) != 0) {
		printk(KERN_ERR "%s:nvlist_lookup_int32 failed,error:%d", 
		    __func__, error);
		goto free_nvl;
	}
	printk(KERN_ERR "%s:cmd:%d", __func__, cmd);

    csrc = kmem_zalloc(sizeof(*csrc), KM_SLEEP);
    csrc->csrc_arg = arg;
    csrc->csrc_cs_data = cs_data;
    csrc->csrc_nvl = nvl;
	switch(cmd) {
		case CS_MSG_SELFUP:
			taskq_dispatch(cs_stat.cs_tq_comm, 
				commsock_hdl_msg_selfup, csrc, TQ_SLEEP);
			break;
		case CS_MSG_ADD_INFO:
			taskq_dispatch(cs_stat.cs_tq_comm, 
				commsock_hdl_msg_addinfo, csrc, TQ_SLEEP);
			break;
		default:
			printk(KERN_WARNING "%s:unsupported msg:%d", 
				__func__, cmd);
			commsock_free_cs_rx_cb_arg(csrc);
			break;
	
	}
    return ;

free_nvl:
    nvlist_free(nvl);
free_cs:
    csh_rx_data_free_ext(cs_data);
}

static int
commsock_brdcast_delself(void)
{
    return 0;
}

static int
commsock_connect_host(commsock_conf_t *attr)
{
    int i = 0;
    int err;
    int opt = 1;
    int32_t sockbuf = 5*1024*1024;
    int hostid = attr->cc_hostid;
    struct socket *sock[CS_HOST_MAX_LINK];
    commsock_lnk_t *lnk = NULL;
    struct sockaddr_in sockaddr;
    struct sockaddr_in cliaddr;
    
    if(mod_hash_find(cs_stat.cs_lnk_snd, 
        (mod_hash_key_t)hostid, &lnk) == 0) {
        printk(KERN_ERR "%s:mod_hash_find the same,hostid:%d", 
            __func__, hostid);
        goto error;
    }
    
    lnk = kzalloc(sizeof(*lnk), GFP_KERNEL);  
    mutex_init(&lnk->cl_mutex, NULL, MUTEX_DEFAULT, NULL); 
    lnk->cl_lnk_cnt = 0;
    lnk->cl_state = CS_LINK_ACTIVE;
    lnk->cl_loc_host = &cs_stat.cs_loc_host;
    lnk->cl_hash_key = hostid;
    spin_lock_init(&lnk->cl_spinlock);
    err = mod_hash_find(cs_stat.cs_hosts, 
        (mod_hash_key_t)attr->cc_ipaddr, &lnk->cl_rem_host);
    if(err != 0) {
        printk(KERN_NOTICE "%s: cs_stat.cs_hosts don't contain host[ip:%s]",
            __func__, attr->cc_ipaddr);
        goto free_lnk;
    }

    bzero(&sock[0], sizeof(sock[0])*CS_HOST_MAX_LINK);
    err = commsock_stat_init_socket(sock);
    if(err != 0) {
        printk(KERN_ERR "%s:init_socket[hostid:%d] failed", 
            __func__, attr->cc_hostid);
        goto error;
    }
    printk(KERN_ERR "%s:commsock_stat_init_socket succeed", __func__);

    for(i=0; i<CS_HOST_MAX_LINK; i++) {
        memset(&cliaddr, 0, sizeof(cliaddr));
    	cliaddr.sin_family = AF_INET;
    	cliaddr.sin_port = htons(
    	    cs_stat.cs_loc_host.cc_port+CS_HOST_MAX_LINK+i);
        if(inet_pton(cs_stat.cs_loc_host.cc_ipaddr, 
            &cliaddr.sin_addr.s_addr) == 0) {
            printk(KERN_ERR "%s:localhost convert to network byteorder failed", __func__);
            goto release_sock;
        }
        err = kernel_bind(sock[i], (struct sockaddr *)&cliaddr, sizeof(cliaddr));
        if(err != 0) {
            printk(KERN_ERR "%s:kernel_bind(ip:%s,port:%d) failed", 
                __func__, cs_stat.cs_loc_host.cc_ipaddr, 
                cs_stat.cs_loc_host.cc_port+CS_HOST_MAX_LINK+i);
            goto release_sock;
        }
        memset(&sockaddr, 0, sizeof(sockaddr));
    	sockaddr.sin_family = AF_INET;
    	sockaddr.sin_port = htons(attr->cc_port+i);
        if(inet_pton(attr->cc_ipaddr, &sockaddr.sin_addr.s_addr) == 0) {
            printk(KERN_ERR "%s:convert to network byteorder failed", __func__);
            goto release_sock;
        }
        err = kernel_connect(sock[i], (struct sockaddr *)&sockaddr, 
            sizeof(sockaddr), O_NONBLOCK);
    	if ((err != -EINPROGRESS) && (err != 0)) {
            printk(KERN_ERR "%s:kernel_connect failed,error:%d", 
                __func__, err);
            goto release_sock;
    	}
    	lnk->cl_lnk_sck[lnk->cl_lnk_cnt++] = sock[i];
    }

    lnk->cl_next_sck = lnk->cl_lnk_sck[0];
    lnk->cl_next_idx = 0;
	printk(KERN_ERR "%s:kernel_connect is inprogress", __func__);

    err = mod_hash_insert(cs_stat.cs_lnk_snd, lnk->cl_hash_key, lnk);
    if(err != 0) {
        printk(KERN_ERR "%s:mod_hash_insert hostid[%d] failed,error:%d", 
            __func__, hostid, err);
        goto free_lnk;
    }
    
    printk(KERN_ERR "%s:mod_hash_insert snd_lnk succeed,ip:%s", 
        __func__, lnk->cl_rem_host->cc_ipaddr);
    return 0;
    
free_lnk:
    kfree(lnk);
release_sock:
//    commsock_stat_release_socket(sock[0]);
error:
    return err;
}

static int
commsock_recv(struct socket *sock, void *buf, size_t len)
{
    int r;
    int flag = MSG_DONTWAIT | MSG_NOSIGNAL;
	struct msghdr	msg = {};
	struct kvec		iov = {buf, len};

	r = kernel_recvmsg(sock, &msg, &iov, 1, 
				len, flag);
    if(r == -EAGAIN)
        r = 0;
    return r;
}

static int
commsock_work_recv(void *arg)
{
	int 				ret;
	struct socket 		*sock = arg;
	struct sockaddr_in  peer_addr;
	int                 addr_len = 0;
	__be32              rem_host_addr;
	struct msghdr 		msg = {NULL, 0};
	struct kvec 		vec = {NULL, 0};
	const size_t		 mdlen = sizeof(commsock_msg_header_t);
	commsock_msg_header_t *msg_header = NULL;	
	commsock_rx_cb_arg_t *dbuf = NULL;
	void 				*buf = NULL;
	commsock_rx_cb_t	*rx;
	void 				(*taskq_fn)(void *);

	if ((error=kernel_getpeername(
	    sock, &peer_addr, &addr_len)) != 0) {
    	pr_info("%s:kernel getpeername failed,error:%d."
    	    "recv thread is going to exit.", 
    		__func__, error);
    	sock_release(sock);
    	return -EFAULT;
	}
	rem_host_addr = peer_addr.sin_addr.s_addr;
/*
	snprintf(ip, CS_IP_LEN, "%d.%d.%d.%d", 
		(unsigned char)pr_addr.sa_data[2],
        (unsigned char)pr_addr.sa_data[3],
        (unsigned char)pr_addr.sa_data[4],
        (unsigned char)pr_addr.sa_data[5]);
    printk(KERN_NOTICE "%s: accept host[ip:%s]",
        __func__, ip); */
    
	memset(&vec,0,sizeof(vec));  
    memset(&msg,0,sizeof(msg));  
loop:
	while (1) {
		dbuf = mempool_alloc(cs_stat.rcv_hd_pool, GFP_KERNEL);
		msg_header = ((char *)dbuf) + sizeof(dbuf);
        vec.iov_base = msg_header;  
        vec.iov_len = mdlen; 
        
        ret = kernel_recvmsg(sock ,&msg, &vec, 1, 
            mdlen, MSG_WAITALL); 
        if ((ret != mdlen) || (msg_header->cm_magic != CS_MAGIC)) {
            pr_warn("commsock received wrong msg header,exit.");
            mempool_free(dbuf, cs_stat.rcv_hd_pool);
            break;
        }

        dbuf->cd_head = NULL;
        dbuf->cd_hlen = 0;
        if (msg_header->cm_hdsz) {
            dbuf->cd_head = ((char *)msg_header) + mdlen;
            dbuf->cd_hlen = msg_header->cm_hdsz;
            vec.iov_base = dbuf->cd_head;
            vec.iov_len = msg_header->cm_hdsz;
            ret = kernel_recvmsg(sock ,&msg, &vec, 1, 
                msg_header->cm_hdsz, MSG_WAITALL); 
            if ((ret != msg_header->cm_hdsz) {
                pr_warn("commsock received wrong header,exit.");
                mempool_free(dbuf, cs_stat.rcv_hd_pool);
                break;
            }
        }

        dbuf->cd_data = NULL;
        dbuf->cd_dlen = 0;
        if (msg_header->cm_dlen) {
            dbuf->cd_data = mempool_alloc(
                cs_stat.rcv_mm_pool, GFP_KERNEL);
            dbuf->cd_dlen = msg_header->cm_dlen;
            vec.iov_base = dbuf->cd_data;
            vec.iov_len = msg_header->cm_dlen;
            ret = kernel_recvmsg(sock ,&msg, &vec, 1, 
                msg_header->cm_dlen, MSG_WAITALL); 
            if ((ret != msg_header->cm_dlen) {
                pr_warn("commsock received wrong data,exit.");
                mempool_free(dbuf, cs_stat.rcv_hd_pool);
                mempool_free(dbuf->cd_data, cs_stat.rcv_mm_pool);
                break;
            }
        }

        /* TODO: find session */
        
	}
out:
	return 0;
} 

static int
commsock_start_recv(commsock_lnk_t *lnk, struct socket *sock)
{
    int error = 0;
    commsock_rcv_arg_t *rcv_arg = NULL;
    
    rcv_arg = kmalloc(sizeof(*rcv_arg), GFP_KERNEL);
    if(!rcv_arg)
        return -ENOMEM;
    rcv_arg->lnk = lnk;
    rcv_arg->sock = sock;
    
    mutex_enter(&lnk->cl_mutex);
    lnk->cl_rcv_task[lnk->cl_rcv_cnt] = kthread_run(
        commsock_work_recv, rcv_arg, "cs_recv_%d_%d", 
        (int)lnk->cl_hash_key, lnk->cl_rcv_cnt);
    if(!IS_ERR(lnk->cl_rcv_task[lnk->cl_rcv_cnt]))
        lnk->cl_rcv_cnt++;
    else
        error = 1;
    mutex_exit(&lnk->cl_mutex);
    if(error) {
        printk(KERN_WARNING, "%s:create recv[%d] thread failed",
            __func__, (int)lnk->cl_hash_key);
        kthread_stop(lnk->cl_rcv_task[lnk->cl_rcv_cnt]);
        kfree(rcv_arg);
    } 
    return error;
}

static void 
commsock_work_accept(void *arg)
{
	int error;
	int opt = 1;
	int32_t sockbuf = 2*1024*1024;
	struct sockaddr_in sockaddr;
	struct socket *nwsock = NULL;
	struct socket *selfsock = arg;
	size_t pr_addr_len = 0;
	struct sockaddr pr_addr;
	char ip[CS_IP_LEN];
	commsock_conf_t *rem_host = NULL;
	commsock_lnk_t *lnk = NULL;
    
    memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = PF_INET;
	sockaddr.sin_port = htons(cs_stat.cs_loc_host.cc_port);
	if(inet_pton(cs_stat.cs_loc_host.cc_ipaddr, 
	    &(sockaddr.sin_addr.s_addr)) != 1) {
        printk(KERN_ERR "%s:inet_pton failed,ip:%s", 
		    __func__, cs_stat.cs_loc_host.cc_ipaddr);
		goto release_slf;
	}
	if( ((error=kernel_bind(selfsock, &sockaddr, sizeof(sockaddr))) < 0) ||
	    ((error=kernel_listen(selfsock, CS_MAX_HOSTS)) != 0) ) {
		printk(KERN_ERR "%s:kernel bind[port:%u] failed, error:%d", 
		    __func__, cs_stat.cs_loc_host.cc_port, error);
		goto release_slf;
	}
    		
	printk(KERN_ERR "%s:ready to accept peer", __func__);
	while(!kthread_should_stop()) {
	    struct inet_connection_sock *conn_sk = inet_csk(selfsock->sk);
	    wait_event_interruptible(*sk_sleep(selfsock->sk), 
	        !reqsk_queue_empty(&conn_sk->icsk_accept_queue) ||
	        kthread_should_stop());
	    if(kthread_should_stop()) {
	        cmn_err(CE_NOTE, "%s,accept thread go exit", __func__);
	        break;
	    }

	    cmn_err(CE_NOTE, "%s:a peer is going to accept", __func__);
		error=kernel_accept(selfsock, &nwsock, O_NONBLOCK);
		if(error == -EAGAIN) {
			goto cont;
		} else if(error != 0) {
            cmn_err(CE_NOTE, "%s: accept failed[%d]",
                __func__, error);
            goto cont;
		}
        printk(KERN_ERR "%s:have accepted a peer", __func__);

        taskq_dispatch(cs_stat.rcv_tq, 
            commsock_work_recv, nwsock, TQ_SLEEP);
		continue;
		
release_nwsck:
    sock_release(nwsock);
cont:
    continue;
	}
release_slf:
    sock_release(selfsock);
out:
    printk(KERN_ERR "%s: accept thread is going to exit", __func__);
}

static int
commsock_start_accpt(void)
{
    int i, j;
	int error = -1;
	
    cs_stat.accpt_wkt = kthread_run(
        commsock_work_accept, 
        cs_stat.sock, "cs_accpt_thread");
    if (IS_ERR(cs_stat.accpt_wkt)) {
        printk(KERN_WARNING, 
            "%s:accept thread create failed",
            __func__);
        return -1;
    }

    return 0;
    
destroy_thread:
	return error;
}

static int 
commsock_stat_store_config(void)
{
    vnode_t *vp = NULL;
    nvlist_t *nvl = NULL;
    int buflen = 0;
    char *buf = NULL;
    int error = SET_ERROR(EFAULT);
    char temp[64] = {0};
    char *ipaddr = cs_stat.cs_loc_host.cc_ipaddr;
    int port = cs_stat.cs_loc_host.cc_port;
    
	if(commsock_check_attrs(&cs_stat.cs_loc_host)) {
        VERIFY(0 == nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP));
        if( (nvlist_add_string(nvl, CS_ATTR_IPADDR, ipaddr) != 0) ||
            (nvlist_add_int32(nvl, CS_ATTR_PORT, port) != 0) ) {
            printk(KERN_WARNING "%s:nvlist add attr failed", __func__);
            goto out;
        }
        
        VERIFY(0 == nvlist_size(nvl, &buflen, NV_ENCODE_XDR));
        VERIFY(0 == nvlist_pack(nvl, &buf, &buflen, NV_ENCODE_XDR, KM_SLEEP));

        if( (vn_open(CS_CONF_STORE_PATH, UIO_SYSSPACE, FCREAT|FWRITE, 0644, &vp, 0, 0) != 0) || 
            (vn_rdwr(UIO_WRITE, vp, buf, buflen, 0, UIO_SYSSPACE, 
                0, RLIM64_INFINITY, kcred, NULL) != 0) ||
            (vn_fsync(vp, FDSYNC, 0, 0) != 0) ) {
            printk(KERN_ERR "%s: store config failed", __func__);
            goto out;
        }
	}
    error = 0;
out:
    if(vp)
        (void)vn_close(vp, 0, 0, 0, 0, 0);
    if(nvl)
        nvlist_free(nvl);
    if(buf)
        kmem_free(buf, buflen);
    return error;
}

/* ENOENT is represent that it's new created */
static int
commsock_stat_load_config(commsock_stat_t *csp)
{
    int error = 0;
    void *buf = NULL;
    nvlist_t *nvlist; 
    struct _buf *file;
    vnode_t *vp;
    uint64_t fsize;

    if((file=kobj_open_file(CS_CONF_STORE_PATH)) == (struct _buf *)-1) {
        error = SET_ERROR(ENOENT);
        goto out;
    }

    /* configure file already exists */
    if( (kobj_get_filesize(file, &fsize) != 0) ||
        ((buf=kmem_alloc(fsize, KM_SLEEP)) == NULL) ||
        (kobj_read_file(file, buf, fsize, 0) < 0) ) {
        printk(KERN_ERR "%s:read conf file failed", __func__);
        error = SET_ERROR(EFAULT);
        goto out;
    }
    
    if(nvlist_unpack(buf, fsize, &nvlist, KM_SLEEP) != 0) {
        printk(KERN_ERR "%s:nvlist_unpack failed", __func__);
        error = SET_ERROR(EFAULT);
        goto out;
    }

    if(commsock_ioc_set_tcp(nvlist, NULL) != 0) {
        printk(KERN_ERR "%s:commsock_ioc_set_tcp failed", __func__);
        error = SET_ERROR(EFAULT); 
    }
    nvlist_free(nvlist);
out:
    if(buf)
        kmem_free(buf, fsize);
    if(file != (struct _buf *)-1)
        kobj_close_file(file);
    return error;
}

static int
commsock_stat_init_socket(struct socket **sockpp)
{
	int error;
	int opt = 1;
	int32_t sockbuf = 2*1024*1024;
	struct socket *sock;
	
    if((error=sock_create_kern(&init_net, PF_INET,
	    SOCK_STREAM, 0, &sock)) != 0) {
        printk(KERN_ERR "%s:socket create failed,error:%d",
			__func__, error);
		goto out;
	}

	if( ((error=kernel_setsockopt(sock, SOL_SOCKET, 
	            SO_REUSEADDR, &opt, sizeof(int))) != 0) || 
	    ((error=kernel_setsockopt(sock, SOL_SOCKET, 
	            SO_REUSEPORT, &opt, sizeof(int))) != 0) ||
	    ((error=kernel_setsockopt(sock, SOL_TCP, 
			    TCP_NODELAY, (char *)&opt, sizeof(opt))) != 0) ||  
	    ((error=kernel_setsockopt(sock, SOL_SOCKET, 
			    SO_RCVBUF, (char *)&sockbuf, sizeof(sockbuf))) != 0) ||
	    ((error=kernel_setsockopt(sock, SOL_SOCKET, 
			    SO_SNDBUF, (char *)&sockbuf, sizeof(sockbuf))) != 0) ) {
        printk(KERN_ERR "%s:kernel_setsockopt failed,error:%d",
            __func__, error);
        goto err_setopt;
	}

	*sockpp = sock;
	
	return 0;
err_setopt:
    sock_release(sock);
out:
	return error;
}

static void
commsock_stat_release_socket(struct socket **sock)
{
    int i = 0;
    for(i = 0; i < CS_HOST_MAX_LINK; i++,sock++)
        sock_release(*sock);
}

static void 
commsock_stat_destroy_taskq(void)
{
    int i = 0;
    commsock_tq_t *cs_tq;
    taskq_t *tq;
    
    for( ; i < sizeof(cs_taskq_vec)/sizeof(commsock_tq_t); i++) {
        cs_tq = &cs_taskq_vec[i];
        tq = *cs_tq->ct_tqpptr;
        if(tq) {
            taskq_destroy(tq);
        }
        cs_tq->ct_state &= ~TASKQ_ACTIVE;
    }
}

static int
commsock_stat_init_taskq(void)
{
    int i = 0, j = 0;
    commsock_tq_t *cs_tq;
    taskq_t *tq;
    
    for( ; i < sizeof(cs_taskq_vec)/sizeof(commsock_tq_t); i++) {
        cs_tq = &cs_taskq_vec[i];
        tq = taskq_create(cs_tq->ct_name, cs_tq->ct_nthr, cs_tq->ct_pri,
            cs_tq->ct_minalloc, cs_tq->ct_maxalloc, cs_tq->ct_flag);
        if(tq == NULL) {
            printk(KERN_ERR "%s:create taskq[%s] failed", 
                __func__, cs_tq->ct_name);
            goto error;
        }
        cs_tq->ct_state |= TASKQ_ACTIVE;
        *(cs_tq->ct_tqpptr) = tq;
    }
    return 0;
error:
    for( ; j < i; j++) {
        cs_tq = &cs_taskq_vec[j];
        taskq_destroy(*(cs_tq->ct_tqpptr));
    }
    return -1;
}

static int
commsock_stat_init_hash(void)
{
    int i=0,j=0;
    mod_hash_t *hash;
    int cnt = sizeof(cs_hash_vec)/sizeof(commsock_mod_hash_t);

    for( ; i<cnt; i++) {
        switch(cs_hash_vec[i].cmp_type) {
            case CS_HASH_TYPE_ID:
                hash = mod_hash_create_idhash(cs_hash_vec[i].cmp_name, 
                    cs_hash_vec[i].cmp_nchain, cs_hash_vec[i].cmp_val_dtor);
                break;
            case CS_HASH_TYPE_PTR:
                hash = mod_hash_create_ptrhash(cs_hash_vec[i].cmp_name, 
                    cs_hash_vec[i].cmp_nchain, cs_hash_vec[i].cmp_val_dtor,
                    cs_hash_vec[i].cmp_key_elem_size);
                break;
            case CS_HASH_TYPE_STR:
                hash = mod_hash_create_strhash(cs_hash_vec[i].cmp_name,
                    cs_hash_vec[i].cmp_nchain, cs_hash_vec[i].cmp_val_dtor);
                break;
            default: break;
        }
        if(hash == NULL) {
            printk(KERN_ERR "%s:ptrhash create failed,index:%d",
                __func__, i);
            goto error;
        }
        *(cs_hash_vec[i].cmp_ptrhash) = hash;
    }
    return 0;
error:
    for( ; j<i; j++) {
        mod_hash_destroy_hash(*(cs_hash_vec[j].cmp_ptrhash));
    }
    return -1;
}

static void
commsock_stat_destroy_hash(void)
{
    int i=0,j=0;
    int cnt = sizeof(cs_hash_vec)/sizeof(commsock_mod_hash_t);
    
    for( ; i<cnt; i++) {
        if(*(cs_hash_vec[i].cmp_ptrhash))
            mod_hash_destroy_hash(*(cs_hash_vec[i].cmp_ptrhash));
    }
}


static void
commsock_init_completion(void)
{

	int i=0;
	int cnt = sizeof(cs_wt_vec)/sizeof(commsock_wt_t);
	struct completion *comp;
	
	for( ; i<cnt; i++) {
		comp = cs_wt_vec[i].cw_comp;
		comp->done = 0;
		init_waitqueue_head(&comp->wait);
	}
}

static int
commsock_stat_init_cache(commsock_stat_t *csp)
{
    csp->cs_rx_data_cache = kmem_cache_create(
        "cs_rx_cache", sizeof(commsock_rx_cb_arg_t), 0, 
        NULL, NULL, NULL, NULL, NULL, 0);
    if(!csp->cs_rx_data_cache) {
        printk(KERN_WARNING "%s:create cache failed",
            __func__);
        return -ENOMEM;
    }
    return 0;
}

static int
commsock_init_stat(commsock_stat_t *csp)
{
    int error;

    mutex_init(&csp->cs_gbmutex, NULL, MUTEX_DEFAULT, NULL);

    /*
     * we ignore error because we can init attrs
     * with commsock_ioc_set_tcp
     */
    (void)commsock_stat_load_config(csp);
    error = commsock_stat_init_cache(csp);
	if((error=commsock_stat_init_socket(&csp->cs_socket)) != 0) {
		printk(KERN_ERR "%s:commsock_stat_init_socket failed,error:%d", 
				__func__, error);
        goto out;
	}
	commsock_init_completion();
	commsock_stat_init_hash();
    error = commsock_stat_init_taskq();
    if(error != 0) {
        printk(KERN_ERR "%s:commsock_stat_init_taskq failed", __func__);
        goto release_sock;
    }
    return 0;
release_sock:
    commsock_stat_release_socket(csp->cs_socket);
out:
    return error;
}

#define CS_MAX_DATA (128<<10)
#define CS_MAX_HEAD (2<<10)
static int __init commsock_init(void)
{
    int i = 0;
    cs_stat.rcv_tq = taskq_create("commsock_rcv_wq", 
        CS_MAX_HOSTS, maxclsyspri, 8, MAX_INT, TASKQ_PREPOPULATE);
    if(!cs_stat.rcv_tq)
        return -ENOMEM; 
    cs_stat.xprt_wq = alloc_workqueue("commsock_xprt_wq", 
        WQ_MEM_RECLAIM|WQ_HIGHPRI, 0);
    if(!cs_stat.xprt_wq) {
        destroy_workqueue(cs_stat.rcv_wq);
        return -ENOMEM;
    }

    cs_stat.rcv_mm_cache = kmem_cache_create("csk_rcv_cache",
        CS_MAX_DATA, 512, SLAB_HWCACHE_ALIGN, NULL);
    cs_stat.rcv_mm_pool = 
        mempool_create_slab_pool(128, cs_stat.rcv_mm_cache);

    cs_stat.rcv_hd_cache = kmem_cache_create("csk_hd_cache",
        CS_MAX_HEAD, 0, SLAB_HWCACHE_ALIGN, NULL);
    cs_stat.rcv_hd_pool = 
        mempool_create_slab_pool(128, cs_stat.rcv_hd_cache);

    commsock_stat_init_socket(&cs_stat.sock);
    commsock_stat_load_config(&cs_stat);
    if(commsock_check_attrs(&cs_stat.cs_loc_host))
        commsock_start_accpt();
    else 
        printk(KERN_INFO "need to config");
    return 0;
    
/*
    int error;
    
    printk(KERN_INFO "commsock module start loading");

    if((error=misc_register(&commsock_dev)) != 0) {
        printk(KERN_ERR "%s: misc_register failed,err:%d",
            __func__, error);
        goto out;
    }

    error = csh_rx_hook_add(CLUSTER_SAN_MSGTYPE_COMMSOCK, 
        commsock_cs_rx_cb, NULL);
    if(error != 0) {
        printk(KERN_ERR "%s:csh_rx_hook_add failed", __func__);
        error= SET_ERROR(EEXIST);
        goto deg_misc;
    } 

    error = commsock_init_stat(&cs_stat);
    if(error != 0) {
        printk(KERN_ERR "%s:commsock_init_stat failed", __func__);
        error= SET_ERROR(EFAULT);
        goto csh_remhk;
    }

    if(commsock_check_attrs(&cs_stat.cs_loc_host)) {
        printk(KERN_INFO "%s:commsock ipaddr:%s, port:%d", 
            __func__, cs_stat.cs_loc_host.cc_ipaddr, 
            cs_stat.cs_loc_host.cc_port);

		if((error=commsock_start_accpt()) != 0) {
			printk(KERN_ERR "%s:commsock_start_accpt failed", __func__);
            goto release_sock;
		}
		
        if((error=commsock_brdcast_selfup()) != 0) {
            printk(KERN_ERR "%s:commsock_brdcast_selfup failed", __func__);
            goto release_sock;
        }
    } else {
        printk(KERN_INFO "%s: config file has no attrs," 
            "need to set tcp", __func__);
    }
	printk(KERN_INFO "commsock module has been loaded successfully!");
        
    return 0;
release_sock:
    commsock_stat_release_socket(cs_stat.cs_socket);
csh_remhk:
    csh_rx_hook_remove(CLUSTER_SAN_MSGTYPE_COMMSOCK);
deg_misc:
    misc_deregister(&commsock_dev);
out:
	printk(KERN_INFO "commsock module load failed!");
    return error;
    */
}

static void __exit commsock_exit(void)
{
    int i = 0;
    printk(KERN_INFO "%s:commsock module start uninstalled", __func__);
/*
    if(cs_stat.cs_thr_accept) {
        for( ; i < CS_HOST_MAX_LINK; i++)
            kthread_stop(cs_stat.cs_thr_accept[i]);
    }
    if(cs_stat.cs_thr_recv)
        kthread_stop(cs_stat.cs_thr_recv);
        */
    if(commsock_stat_store_config() != 0) {
        printk(KERN_WARNING "%s:commsock_stat_store_config failed", __func__);
    }
    
	if(csh_rx_hook_remove(CLUSTER_SAN_MSGTYPE_COMMSOCK) != 0) {
        printk(KERN_WARNING "%s:csh_rx_hook_remove %d failed", 
            __func__, CLUSTER_SAN_MSGTYPE_COMMSOCK);
    }
    
    commsock_stat_destroy_taskq();
    commsock_stat_release_socket(cs_stat.cs_socket);
    commsock_stat_destroy_hash();
    kmem_cache_destroy(cs_stat.cs_rx_data_cache);
    misc_deregister(&commsock_dev);
    printk(KERN_INFO "%s:commsock module uninstalled successfully!", __func__);
}

module_init(commsock_init);
module_exit(commsock_exit);
MODULE_LICENSE("GPL");

EXPORT_SYMBOL(commsock_host_send_msg);
EXPORT_SYMBOL(commsock_broadcast_msg);
EXPORT_SYMBOL(commsock_register_rx_cb);
EXPORT_SYMBOL(commsock_deregister_rx_cb);
EXPORT_SYMBOL(commsock_free_rx_cb_arg);

