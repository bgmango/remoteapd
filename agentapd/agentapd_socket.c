#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/handlers.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
//#include <netlink/types.h>
//#include <netlink/socket.h>

#define NL_SOCK_PASSCRED    (1<<1)

#define SERVPORT 8888 /*服务器监听端口号 */
#define MAX_MSG_SIZE 2048 /*最大缓冲区字节*/
#define BACKLOG 10 /* 最大同时连接请求数 */

int sockfd, client_fd;
struct sockaddr_in agent_addr;
struct sockaddr_in hapd_addr;
static uint32_t port_bitmap[32] = { 0 };

struct nl_handle
{
      struct sockaddr_nl      h_local;
      struct sockaddr_nl      h_peer;
      int               h_fd;
      int               h_proto;
      unsigned int            h_seq_next;
      unsigned int            h_seq_expect;
      int               h_flags;
      struct nl_cb *          h_cb;
};

struct nl_msg
{
      int               nm_protocol;
      int               nm_flags;
      struct sockaddr_nl      nm_src;
      struct sockaddr_nl      nm_dst;
      struct ucred*            nm_creds;
      struct nlmsghdr * nm_nlh;
      size_t                  nm_size;
};

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *err = arg;
	*err = 0;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	int *ret = arg;
	*ret = err->error;
	return NL_SKIP;
}


static int no_seq_check(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

static struct nl_handle *nl80211_handle_alloc(void *cb)
{
	struct nl_handle *handle;
	uint32_t pid = getpid() & 0x3FFFFF;
	int i;

	handle = nl_handle_alloc_cb(cb);

	for (i = 0; i < 1024; i++) {
		if (port_bitmap[i / 32] & (1 << (i % 32)))
			continue;
		port_bitmap[i / 32] |= 1 << (i % 32);
		pid += i << 22;
		break;
	}

	nl_socket_set_local_port(handle, pid);

	return handle;
}

int netlink_init()
{
	//struct netlink_data *netlink;
	struct sockaddr_nl local;
	int sock;
	//netlink = os_zalloc(sizeof(*netlink));
	//if (netlink == NULL)
	//	return NULL;

	sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		printf("netlink: Failed to open netlink socket\n");
		//netlink_deinit(netlink);
		return 1;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK;
	if (bind(sock, (struct sockaddr *) &local, sizeof(local)) < 0)
	{
		printf("netlink: Failed to bind netlink socket\n");
		//netlink_deinit(netlink);
		return 1;
	}

	return 0;
}

static void nl80211_handle_destroy(struct nl_handle *handle)
 {
   uint32_t port = nl_socket_get_local_port(handle);
   
   port >>= 22;
   port_bitmap[port / 32] &= ~(1 << (port % 32));
 
   nl_handle_destroy(handle);
 }


static struct nl_handle * nl_create_handle(struct nl_cb *cb)
{
	struct nl_handle *handle;

	handle = nl80211_handle_alloc(cb);
	if (handle == NULL) {
		printf("nl80211: Failed to allocate netlink callbacks\n");
		return NULL;
	}

	if (genl_connect(handle)) {
		printf("nl80211: Failed to connect to generic netlink\n");
		nl80211_handle_destroy(handle);
		return NULL;
	}

	return handle;
}

int my_nl_sendmsg(struct nl_handle *handle, struct nl_msg *msg, struct msghdr *hdr)
 {
         int ret;
 
         struct iovec iov = {
                 .iov_base = (void *) nlmsg_hdr(msg),
                 .iov_len = nlmsg_hdr(msg)->nlmsg_len,
         };

         hdr->msg_iov = &iov;
         hdr->msg_iovlen = 1;
 	 printf("sending msg to hostapd\n");
         ret = sendmsg(client_fd, hdr, 0);
         if (ret < 0)
		return -1;
         return ret;
}

int my_nl_send(struct nl_handle *handle, struct nl_msg *msg)
{
         struct sockaddr_nl *dst;
         struct ucred *creds;
         
         struct msghdr hdr = {
                 .msg_name = (void *) &handle->h_peer,
		 .msg_namelen = sizeof(struct sockaddr_nl),
         };
         dst = nlmsg_get_dst(msg);
         if (dst->nl_family == AF_NETLINK)
                 hdr.msg_name = dst;
	
        creds = nlmsg_get_creds(msg);
         if (creds != NULL) {
                char buf[CMSG_SPACE(sizeof(struct ucred*))];
                 struct cmsghdr *cmsg;
 
                 hdr.msg_control = buf;
                 hdr.msg_controllen = sizeof(buf);
 
                 cmsg = CMSG_FIRSTHDR(&hdr);
                 cmsg->cmsg_level = SOL_SOCKET;
                 cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred*));
                 memcpy(CMSG_DATA(cmsg), creds, sizeof(struct ucred*));
         }
         
	return my_nl_sendmsg(handle, msg, &hdr); 
}

int my_nl_send_auto_complete(struct nl_handle *handle, struct nl_msg *msg)
{
         return my_nl_send(handle, msg);
}

int msgFormat(char *pdu, struct nl_msg *msg)
{
	struct nl_msg *p = (struct nl_msg*)pdu;
	msg->nm_protocol = p->nm_protocol;
	msg->nm_flags = p->nm_flags;
	msg->nm_src = p->nm_src;
	msg->nm_dst = p->nm_dst;
	msg->nm_creds = p->nm_creds;
	msg->nm_nlh = p->nm_nlh;
	msg->nm_size = p->nm_size;
	return 0;
}

int main() {
	struct sockaddr_in agent_addr;
	struct sockaddr_in hapd_addr;
	char recvbuf[MAX_MSG_SIZE];
	struct nl_msg *msg;
	int err = 0, sin_size;
	struct nl_cb *cb;
	struct nl_handle *nl_event;
	void *drv, *w, *global;
	msg = nlmsg_alloc();
	if (!msg) {
		printf("msg alloc failed\n");
		return 0;
	}
	if(netlink_init()) {
		printf("netlink init failed\n");
		exit(1);	
	}
	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if(cb == NULL) {
		printf("nl80211: Failed to allocate netlink callbacks \n");	
		exit(1);
	}
	nl_event = nl_create_handle(cb);
	if(nl_event == NULL) {
		printf("nl80211: Failed to create netlink callbacks\n");	
		exit(1);
	}
	if((sockfd = socket(AF_INET,SOCK_STREAM,0)) < 0) {
		perror("TCP socket create error！");
		exit(1);	
	}
	bzero(&agent_addr, sizeof(agent_addr));	
	agent_addr.sin_family = AF_INET;
	agent_addr.sin_port = htons(SERVPORT);
	agent_addr.sin_addr.s_addr=htonl(INADDR_ANY);
	if(bind(sockfd,(struct sockaddr*)&agent_addr, sizeof(struct sockaddr)) < 0) {
		perror("bind socket error");
		exit(1);	
	}
	if(listen(sockfd, BACKLOG) < 0) {
		perror("listen socket error!");
		exit(1);	
	}
	while(1) {
		sin_size = sizeof(struct sockaddr_in);
		if((client_fd = accept(sockfd,(struct sockaddr *)&hapd_addr,&sin_size)) <= 0) {
			perror("accept error！");
			continue;	
		}
		else {
			printf("start receive msg from hostapd:\n");
			if(!fork()) {
			//memset(recvbuf,0,MAX_MSG_SIZE);
			int len;
			if((len = recv(client_fd, recvbuf, MAX_MSG_SIZE, 0)) < 0) {
				printf("recv error\n");
				close(client_fd);
				close(sockfd);
				exit(1);
			}
			msgFormat(recvbuf,msg);
			err = my_nl_send_auto_complete(nl_event,msg);
			if(err < 0) {
				perror("nl_send_auto_complete error!");
				nl_cb_put(cb);
				nlmsg_free(msg);
				return 0;
			}
			close(client_fd);
			exit(0);
			}
		}
		close(client_fd);
	}
	close(sockfd);
	return 0;
}
