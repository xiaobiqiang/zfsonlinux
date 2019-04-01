#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <sys/cmn_err.h>
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

static void __init
vmptt_mac_init(void)
{
	struct net_device *dev = NULL;
	
	for_each_netdev(&init_net, dev) {
		cmn_err(CE_NOTE, "%s:netdev_name:%s,netdev_mc:",
			__func__, dev->name);
	}
}

static void __exit
vmptt_mac_fini(void)
{

}


module_init(vmptt_mac_init);
module_exit(vmptt_mac_fini);
MODULE_LICENSE("GPL");
