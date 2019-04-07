#ifndef _LINUX_COMMSOCK_H
#define _LINUX_COMMSOCK_H

#include <linux/net.h>
#include <sys/modhash.h>
#include <linux/uio.h>
#include <sys/condvar.h>
#include <sys/mutex.h>
#include <linux/types.h>

#define CS_CONF_STORE_PATH  "/etc/commsock.cache"

/* configure attr string */
#define CS_ATTR_IPADDR      "ipaddr"
#define CS_ATTR_PORT        "port"
#define CS_ATTR_HOSTID      "hostid"

#define CS_BRDCAST_SESSION  CLUSTER_SAN_BROADCAST_SESS
#define CS_MSG_SELFUP       0x01
#define CS_MSG_ADD_INFO     0x02
#define CS_MSG_VMPT3SAS     0x0A

#define CS_MAX_HOSTS        16
#define CS_HOSTNAME_LEN		32
#define CS_IP_LEN			16
#define CS_HOST_MAX_LINK    4

typedef struct commsock_conf {
	mod_hash_key_t cc_key;
    int     cc_hostid;
    int     cc_port;
    char    cc_ipaddr[CS_IP_LEN];
	struct completion cc_notify_recv;
} commsock_conf_t;

typedef struct commsock_rx_cb_arg {
	struct list_head entry;
	void 	*cd_session;
	u32		cd_type;
	void	*cd_cb_arg;
	void	(*callack)(void *);
	void 	*cd_data;
	void    *cd_head;
	size_t	 cd_dlen;
	size_t   cd_hlen;
	/* msg header */
	/* header */
} commsock_rx_cb_arg_t;

typedef struct commsock_cmd {
    uint64_t	cc_nvlist_src;	
    uint64_t	cc_nvlist_src_size;
    uint64_t	cc_nvlist_dst;	
    uint64_t	cc_nvlist_dst_size;
} commsock_cmd_t;

typedef enum commsock_ioc_cmd {
    COMMSOCK_IOC_FIRST = 0x00,
    COMMSOCK_IOC_SET_TCP = 0x01,
    COMMSOCK_IOC_GET_TCP = 0x02,
    COMMSOCK_IOC_EOF
} commsock_ioc_cmd_e;

typedef struct commsock_rx_worker {
	struct list_head	task_wait;
	struct list_head	task_xmit;
	struct list_head	*ts_wait;
	struct list_head	*ts_xmit;
	struct task_struct 	*worker;
	kmutex_t		worker_mtx;
	kcondvar_t		worker_cv;
	uint32_t		worker_flags;
	uint32_t		worker_ntasks;
	void			*worker_private;
	uint32_t		worker_index;
} commsock_rx_worker_t;

#define COMMSOCK_LNK_WORKER	4
typedef struct commsock_lnk {
	mod_hash_key_t  cl_hash_key;
	commsock_conf_t *cl_loc_host;
	commsock_conf_t *cl_rem_host;
	struct socket	*cl_sck;
	int 			cl_state;

	commsock_rx_worker_t *cl_works[COMMSOCK_LNK_WORKER];
} commsock_lnk_t;

typedef enum commsock_lnk_state {
	CS_LINK_ACTIVE 	= 0x01,
	CS_LINK_DOWN 	= 0x02
} commsock_lnk_state_e;

extern int commsock_host_send_msg(void *sess, uint_t type, 
    void *header, size_t hdsz, 
    struct kvec *vecp, size_t cnt, size_t dlen);

extern void
commsock_broadcast_msg(uint_t type, void *header, size_t hdsz);

extern int 
commsock_register_rx_cb(uint_t, void (*)(commsock_rx_cb_arg_t *), void *);

extern void *
commsock_deregister_rx_cb(uint_t type);

extern void 
commsock_free_rx_cb_arg(commsock_rx_cb_arg_t *arg);
#endif
