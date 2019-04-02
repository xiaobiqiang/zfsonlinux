#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <sys/cmn_err.h>
#include <linux/if.h>
#include <linux/slab.h>
#include <uapi/linux/utsname.h>
#include <sys/kobj.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/nvpair.h>
#include <sys/nvpair_impl.h>
#include <linux/types.h>
#include <sys/types.h>


#define VMPTT_HOSTNAME_LEN	16
#define ETHER_ADDR_LEN 		6
#define VMPTT_CFG_FILE		"/etc/vmptt_trsp.cache"
#define	VMPTT_CFG_IFNAME	"if_name"

/*
#define ETHER_ADDR_LEN 		6
#define VMPTT_MAC_MAGIC		0x12345678
static u8 vmptt_brdcast_mac[6] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

struct ether_header {
	u8 	ether_dmac[ETHER_ADDR_LEN];
	u8 	ether_smac[ETHER_ADDR_LEN];
	u16 ether_type;
} __packed;

typedef struct {
	u32 magic;
	u32 type;
	u32 hdsz;
	u32 dtsz;
	u64	req_idx;
	u32 req_idx_partno;
} vmptt_mac_header_t;

typedef struct {
	u8 		mc_addr[ETHER_ADDR_LEN];
	s8 		hostname[32];	
	u32 	hostid;
} vmptt_host_info_t;

typedef struct {
	vmptt_host_info_t 	lc_host;
	struct net_device *	lc_netdev;
	struct list_head 	rm_hosts;
	u64					req_idx;
	kmutex_t			mutex;
	
} vmptt_global_t;

static vmptt_global_t p_global = NULL;

static u32 
vmptt_mac_getsize(struct kvec *vec, u32 cnt)
{
	u32 iter = 0;
	u32 size = 0;

	for ( ; iter < cnt; iter++, vec++)
		size += vec->iov_len;
	return size;
}

static void 
vmptt_fill_mac_header(vmptt_host_info_t *host, struct sk_buff *skbp)
{
	u16 ether_type = ETHERTYPE_ARP;
	
	skb_reset_mac_header(skbp);
	memcpy(skb_put(skbp, ETHER_ADDR_LEN,
		host->mc_addr, ETHER_ADDR_LEN);
	memcpy(skb_put(skbp, ETHER_ADDR_LEN),
		p_global->lc_host.mc_addr, ETHER_ADDR_LEN);
	memcpy(skb_put(skbp, 2), &ether_type, 2);
}

static void
vmptt_fill_xmit_header(u32 type, u32 hdsz, u32 dtsz, struct sk_buff *skbp)
{
	vmptt_mac_header_t header = {
		VMPTT_MAC_MAGIC, type, hdsz, dtsz};
		
	header.req_idx = ++p_global->req_idx;
	header.req_idx_partno = header.req_idx;
	memcpy(skb_put(skbp, sizeof(header), 
		&header, sizeof(header));
}

static void
vmptt_fill_xmit_msg(vmptt_raw_data_t *rw_data, struct sk_buff *skbp)
{
	u32 iter = 0;
	u32 totlen = rw_data->vsz;
	struct kvec *vecp = rw_data->vec;
	char *start = skb_put(skbp, totlen);

	for ( ; iter < rw_data->vcnt; 
		iter++, vecp++) {
		memcpy(start, vecp->iov_base, vecp->iov_len);
		start += vecp->iov_len;
	}
}

static s32 
vmptt_mac_prepare(vmptt_xmit_t *sx_data, struct sk_buff **skbpp)
{
	vmptt_raw_data_t *raw = sx_data->data;
	vmptt_host_info_t *rhost = sx_data->cookie;
	u32 hdsz = vmptt_mac_getsize(raw->vec, raw->hd_vcnt);
	u32 dtsz = vmptt_mac_getsize(raw->vec+raw->hd_vcnt, 
		raw->dt_vcnt);	
	struct sk_buff *skbp = NULL;
	struct net_device *dev = p_global->lc_netdev;
	if(!dev)
		return -ENODEV;
	
	skbp = alloc_skb(hdsz+dtsz+2, GFP_ATOMIC);
	if (!skbp)
		return -ENOMEM;

	skb_reserve(skbp, 2);
	vmptt_fill_mac_header(rhost, skbp);
	vmptt_fill_xmit_header(sx_data->msg, raw->hd_vcnt,
		raw->dt_vcnt, skbp);
	vmptt_fill_xmit_msg(raw, skbp);
	skbp->dev = dev;

	*skbpp = skbp;
	return 0;
}

static s32
vmptt_mac_submit_tran(vmptt_xmit_t *xm_data, struct sk_buff *skbp)
{
	return dev_queue_xmit(skbp);
}
*/

struct vmptt_host_attr {
	struct list_head entry;
	s8	hostname[VMPTT_HOSTNAME_LEN];
	u32	hostid;
	s8 	if_name[IFNAMSIZ];
	u8	if_mac[ETHER_ADDR_LEN];
	u8	pad[2];
};

struct vmptt_mac_info {
	struct vmptt_host_attr *lc_p;
	struct net_device	   *lc_netdev;
	struct list_head	   *hosts_head;
//	struct nvlist		   *lc_nvl;
	/* local host first */
	struct vmptt_host_attr	hosts;
	/* is if_name been configed? */
	boolean_t				is_enabled;
};

static struct vmptt_mac_info *gp_vmptt_info = NULL;

static s32
vmptt_mac_load_config(vmptt_mac_info *pinf)
{
	s32 err = 0;
	struct new_utsname *sys = utsname();
	struct vmptt_host_attr *attr = pinf->lc_p;
	struct net_device *dev = NULL;
	boolean_t found_netdev = B_FALSE;
	void *buf = NULL;
	nvlist_t *nvlist = NULL;
	const char *pathname = VMPTT_CFG_FILE;
	struct _buf *file = NULL;
	u64 fsize = 0;

	INIT_LIST_HEAD(&attr->entry);
	attr->hostid = zone_get_hostid(NULL);
	strncpy(attr->hostname, sys->sysname, VMPTT_HOSTNAME_LEN);
	
	file = kobj_open_file(pathname);
	if (file == (struct _buf *)-1)
		return -ENOENT;

	err = kobj_get_filesize(file, &fsize);
	if (!err) 
		goto out;

	buf = kmem_alloc(fsize, KM_SLEEP);
	err = kobj_read_file(file, buf, fsize, 0)
	if (err < 0)
		goto out;

	err = nvlist_unpack(buf, fsize, &nvlist, KM_SLEEP);
	if (err != 0)
		goto out;

	if ( ((err = nvlist_lookup_string(nvlist, 
			VMPTT_CFG_IFNAME, &attr->if_name)) != 0) ) {
		goto free_nvl;
	}

	for_each_netdev(&init_net, dev) {
		if ( (strcmp(attr->if_name, dev->name) == 0) &&
			 (dev->addr_len == ETHER_ADDR_LEN) ) {
			bcopy(dev->dev_addr, 
				attr->if_mac, ETHER_ADDR_LEN)
			found_netdev = B_TRUE;
		}
	}

	if (!found_netdev)
		err = -ENODEV;

free_nvl:
	nvlist_free(nvlist);
out:
	if (buf != NULL)
		kmem_free(buf, fsize);

	kobj_close_file(file);
	return err;
}

static s32
vmptt_mac_init_gbinfo(vmptt_mac_info **ppinf)
{
	s32 err = 0;
	vmptt_mac_info *info = NULL;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		pr_err("allocate mem for gbinfo failed in %s",
			__func__);
		err = -ENOMEM;
		goto error;
	}

	info->lc_p = &info->hosts;
	info->hosts_head = &info->hosts.entry;
	err = vmptt_mac_load_config(info);
	if (err == -ENOENT) {
		pr_info("haven't config yet, maybe you need "
				"to config to make vmpt_trsp work.");
		err = 0;
		info->is_enabled = B_FALSE;
	} else if (err != 0) {
		pr_info("something is wrong when loading stored "
				"config. error is %d", err);
		goto free_inf;
	} else
		info->is_enabled = B_TRUE;

	*ppinf = info;
	return 0;
	
free_inf:
	kfree(info);
error:
	return err;
}

static int __init
vmptt_mac_init(void)
{
	s32 err;
	
	err = vmptt_mac_init_gbinfo(&gp_vmptt_info);
	if (err) {
		pr_err("initialize global configure info failed "
			"when loading vmpt_trsp, error is %d", err);
		goto out;
	}

	if (!gp_vmptt_info->is_enabled) {
		pr_info("vmpt_trsp haven't been configured yet.")
		goto out;
	}

	/* TODO: broadcast message to inform selfup */
	
out:
	return err;
}

static void __exit
vmptt_mac_fini(void)
{

}


module_init(vmptt_mac_init);
module_exit(vmptt_mac_fini);
MODULE_LICENSE("GPL");
