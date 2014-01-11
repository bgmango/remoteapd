#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netinet/in.h>  
#include <arpa/inet.h> 
#include<sys/socket.h>
//#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/handlers.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include "adapter.h"

#define PORT 8888  
#define SERVER_IP "127.0.0.1"

struct sockaddr_in servaddr;
int listenfd;

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


struct nl_cb
{
      nl_recvmsg_msg_cb_t cb_set[NL_CB_TYPE_MAX+1];
      void * cb_args[NL_CB_TYPE_MAX+1];
      
      nl_recvmsg_err_cb_t cb_err;
      void * cb_err_arg;

      /** May be used to replace nl_recvmsgs with your own implementation
       * in all internal calls to nl_recvmsgs. */
      int (*cb_recvmsgs_ow)(struct nl_handle *, struct nl_cb *);

      /** Overwrite internal calls to nl_recv, must return the number of
       * octets read and allocate a buffer for the received data. */
      int (*cb_recv_ow)(struct nl_handle *,struct sockaddr_nl *, unsigned char **);

      /** Overwrites internal calls to nl_send, must send the netlink
       * message. */
      int (*cb_send_ow)(struct nl_handle *, struct nl_msg *);
};



int adapter_socket_init() {
	if((listenfd= socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("socket error\n");
		return -1;
	}

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	servaddr.sin_addr.s_addr = inet_addr(SERVER_IP);
	
	if(connect(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		printf("connect socket error");
		return -1;
	}
	return 0;
}

static int NL_cb_call(struct nl_cb *cb, int type, struct nl_msg *msg)
{
        int ret;
	printf("nl_cb_call:type = %d\n",type);
        //cb->cb_active = type;
        ret = cb->cb_set[type](msg, cb->cb_args[type]);
	printf("ret=%d\n",ret);
        //cb->cb_active = __NL_CB_TYPE_MAX;
        return ret;
	//return cb->cb_set[type](msg, cb->cb_args[type]);
}

int NL_cb_err(struct nl_cb *cb, enum nl_cb_kind kind, nl_recvmsg_err_cb_t func, void *arg)
{ 
  if (kind < 0 || kind > NL_CB_KIND_MAX)
  //return -NLE_RANGE;
	return -1;
 
 if (kind == NL_CB_CUSTOM) {
  cb->cb_err = func;
  cb->cb_err_arg = arg;
  } 
  return 0;
}

int NL_cb_set(struct nl_cb *cb, enum nl_cb_type type, enum nl_cb_kind kind, nl_recvmsg_msg_cb_t func, void *arg)
{
 if (type < 0 || type > NL_CB_TYPE_MAX)
  //return -NLE_RANGE;
	return -1;
 
  if (kind < 0 || kind > NL_CB_KIND_MAX)
  //return -NLE_RANGE;
	return -1;
 
 if (kind == NL_CB_CUSTOM) {
	printf("NL_cb_set\n");
  cb->cb_set[type] = func;
  cb->cb_args[type] = arg;
  } 
  return 0;
}

#define NL_CB_CALL(cb, type, msg) \
do { \
         err = NL_cb_call(cb, type, msg); \
         switch (err) { \
         case NL_OK: \
		 printf("NL_OK\n"); \
                 err = 0; \
                 break; \
         case NL_SKIP: \
		 printf("NL_SKIP\n");\
                 goto skip; \
        case NL_STOP: \
                 goto stop; \
         default: \
                 goto out; \
         } \
} while (0)

#define NL_MSG_PEEK (1<<3)
#define NL_SOCK_PASSCRED (1<<1)
static int nl_recv_adpa(struct nl_handle *handle, struct sockaddr_nl *nla, unsigned char **buf, struct ucred **creds)
{
         int n=0;
	 int flags = 0;
         static int page_size = 0;
         struct iovec iov;
         struct msghdr msg = {
                 .msg_name = (void *)nla,
                 .msg_namelen = sizeof(struct sockaddr_nl),
                 .msg_iov = &iov,
                 .msg_iovlen = 1,
                 .msg_control = NULL,
                 .msg_controllen = 0,
                 .msg_flags = 0,
         };
	 struct cmsghdr *cmsg;
 	 if (handle->h_flags & NL_MSG_PEEK)
                 flags |= MSG_PEEK;
         if (page_size == 0)
                 page_size = getpagesize();
 	 
         iov.iov_len = page_size;
         iov.iov_base = *buf = calloc(1, iov.iov_len);
		
         if (handle->h_flags & NL_SOCK_PASSCRED) {
                 msg.msg_controllen = CMSG_SPACE(sizeof(struct ucred*));
                 msg.msg_control = calloc(1, msg.msg_controllen);
         }
 	 
 retry:
	 n = recvmsg(listenfd, &msg, flags);
	 msg.msg_namelen = sizeof(struct sockaddr_nl);
	 if (!n)
                goto abort;
	 else if (n < 0) {
                 if (errno == EINTR) {
                         printf("recvmsg() returned EINTR, retrying\n");
                         goto retry;
                 } else if(errno == EAGAIN) {
                         printf("recvmsg() returned EAGAIN, aborting\n");
                         goto abort;
		}else {
			 free(msg.msg_control);
                         free(*buf);
                         printf("recvmsg failed");
			 goto abort;
		}
		
         }
	  if (iov.iov_len < n ||
             msg.msg_flags & MSG_TRUNC) {
	         printf("iov & msg.msg_flags & MSG_TRUNC\n");
                 /* Provided buffer is not long enough, enlarge it
                  * and try again. */
                 iov.iov_len *= 2;
                 iov.iov_base = *buf = realloc(*buf, iov.iov_len);
                 goto retry;
	 }
	 else if (msg.msg_flags & MSG_CTRUNC) {
		 printf("msg.msg_flags & MSG_TRUNC\n");
                 msg.msg_controllen *= 2;
                 msg.msg_control = realloc(msg.msg_control, msg.msg_controllen);
                 goto retry;
         } else if (flags != 0) {
		  printf("flags");
                 /* Buffer is big enough, do the actual reading */
                 flags = 0;
                 goto retry;
         }
	 if (msg.msg_namelen != sizeof(struct sockaddr_nl)) {
		 printf("socket address size mismatch\n");
		 goto abort;
         }
	  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                 if (cmsg->cmsg_level == SOL_SOCKET) {
                         *creds = calloc(1, sizeof(struct ucred*));
                         memcpy(*creds, CMSG_DATA(cmsg), sizeof(struct ucred*));
                         break;
                 }
         }
	 free(msg.msg_control);
	 close(listenfd);
	 return n;
abort:
         free(msg.msg_control);
         free(*buf);
         return 0;
}
static int nl_recvmsgs_adpa(struct nl_handle *handle, struct nl_cb *cb)
{
	int n, err = 0;
	struct nlmsghdr *hdr;
	int multipart = 0;
	struct sockaddr_nl nla = {0};
	struct nl_msg *msg = NULL;
	struct ucred *creds = NULL;
	unsigned char *buf = NULL;
continue_reading:
	
	n = nl_recv_adpa(handle,&nla,&buf,&creds);
	if(n <= 0)
		return n;
	hdr = (struct nlmsghdr *)buf;
	while (nlmsg_ok(hdr, n)) {
		printf("nlmsg_ok\n");
		nlmsg_free(msg);
		msg = nlmsg_convert(hdr);
		if (!msg) {
			printf("msg error\n");
			err=-1;
			//err = nl_errno(ENOMEM);
			goto out;
		}

		nlmsg_set_proto(msg, handle->h_proto);
		//nlmsg_set_src(msg, &nla);
		/*if (creds)
			nlmsg_set_creds(msg, creds);
		if (cb->cb_set[NL_CB_MSG_IN])
			NL_CB_CALL(cb, NL_CB_MSG_IN, msg);
		if (cb->cb_set[NL_CB_SEQ_CHECK])
			NL_CB_CALL(cb, NL_CB_SEQ_CHECK, msg);
		else if (hdr->nlmsg_seq != handle->h_seq_expect){
			if (cb->cb_set[NL_CB_INVALID])
				NL_CB_CALL(cb, NL_CB_INVALID, msg);
			else {
				//err=-1;
				//err = nl_error(EINVAL,
					//"Sequence number mismatch");
				printf("Sequence number mismatch\n");				
				//goto out;
			}
		}
		if (hdr->nlmsg_type == NLMSG_DONE ||
		    hdr->nlmsg_type == NLMSG_ERROR ||
		    hdr->nlmsg_type == NLMSG_NOOP ||
		    hdr->nlmsg_type == NLMSG_OVERRUN) {
			handle->h_seq_expect++;
			//NL_DBG(3, "recvmsgs(%p): Increased expected " \
			       "sequence number to %d\n",
			  //     handle, handle->h_seq_expect);
		}

		if (hdr->nlmsg_flags & NLM_F_MULTI)
			multipart = 1;
	
		if (hdr->nlmsg_flags & NLM_F_ACK) {
			if (cb->cb_set[NL_CB_SEND_ACK])
				NL_CB_CALL(cb, NL_CB_SEND_ACK, msg);
			else {
				
			}
		}
		if (hdr->nlmsg_type == NLMSG_DONE) {
			multipart = 0;
			if (cb->cb_set[NL_CB_FINISH]) {
				NL_CB_CALL(cb, NL_CB_FINISH, msg);
			}
		}else if (hdr->nlmsg_type == NLMSG_NOOP) {
			if (cb->cb_set[NL_CB_SKIPPED])
				NL_CB_CALL(cb, NL_CB_SKIPPED, msg);
			else {
				printf("goto skip\n");
				goto skip;
			     }
		}else if (hdr->nlmsg_type == NLMSG_OVERRUN) {
			if (cb->cb_set[NL_CB_OVERRUN])
				NL_CB_CALL(cb, NL_CB_OVERRUN, msg);
			else {
				printf("Overrun\n");
				err=-1;
			//	err = nl_error(EOVERFLOW, "Overrun");
				goto out;
			}
		}

		
		else if (hdr->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *e = nlmsg_data(hdr);
			printf("nlmsg_next3\n");
			if (hdr->nlmsg_len < nlmsg_msg_size(sizeof(*e))) {
				if (cb->cb_set[NL_CB_INVALID])
					NL_CB_CALL(cb, NL_CB_INVALID, msg);
				else {
					printf("Truncated error\n");
					err=-1;
					//err = nl_error(EINVAL,
					  //      "Truncated error message");
					goto out;
				}
			} else if (e->error) {		
			    if (cb->cb_err) {
					printf("cb->cb_err\n");
					err = cb->cb_err(&nla, e,
						   cb->cb_err_arg);
					if (err < 0) {
						printf("err<0\n");
						goto out;
					}
					else if (err == NL_SKIP) {
						printf("err:goto skip\n");
						goto skip;
					}
					else if (err == NL_STOP) {
						printf("err:Netlink Error\n");
						err=-1;
						//err = nl_error(-e->error,
						//         "Netlink Error");
						goto out;
					}
				} else {
				printf("Netlink Error\n");
				err=-1;
				//err = nl_error(-e->error,
					//	  "Netlink Error");
				goto out;
				}
			} else if (cb->cb_set[NL_CB_ACK]) {
				NL_CB_CALL(cb, NL_CB_ACK, msg);
				goto skip;
			}
		} */
		//else {
			if (cb->cb_set[NL_CB_VALID]) {
				NL_CB_CALL(cb, NL_CB_VALID, msg);
			}
	    	//}
skip:
		err = 0;
		hdr = nlmsg_next(hdr, &n);
	}
	nlmsg_free(msg);
	free(buf);
	free(creds);
	buf = NULL;
	msg = NULL;
	creds = NULL;
	//if (multipart) {
//		/* Multipart message not yet complete, continue reading */
	//	goto continue_reading;
	//}
stop:
	err = 0;
out:
	nlmsg_free(msg);
	free(buf);
	free(creds);
	return err;
}

int pduFormat(char *pdu, struct nl_msg *msg) 
{
	struct nl_msg *p = (struct nl_masg*)pdu;
	p->nm_protocol = msg->nm_protocol;
	p->nm_flags = msg->nm_flags;
	p->nm_src = msg->nm_src;
	p->nm_dst = msg->nm_dst;
	p->nm_creds = msg->nm_creds;
	p->nm_nlh = msg->nm_nlh;
	p->nm_size = msg->nm_size;
	return 0;
}

int nl_send_auto_complete_apda(struct nl_handle *handle,struct nl_msg *msg)
{
	struct nlmsghdr *nlh;
	struct nl_cb *cb = handle->h_cb;
        int ret = 0;
	nlh = nlmsg_hdr(msg);
        if (nlh->nlmsg_pid == 0)
                nlh->nlmsg_pid = handle->h_local.nl_pid;
 
        if (nlh->nlmsg_seq == 0)
                 nlh->nlmsg_seq = handle->h_seq_next++;
 	if (msg->nm_protocol == -1)
                 msg->nm_protocol = handle->h_proto;
	//msg->nm_flags |= (NLM_F_REQUEST | NLM_F_ACK);
	if (cb->cb_send_ow)
                return cb->cb_send_ow(handle, msg);
        else {
	int ret1;
	ret1 = adapter_socket_init();
	if(ret1 < 0) {
		printf("adapter_socket_init fail\n");
		close(listenfd);
		return -1;
	}
	char sendbuf[2048];
	pduFormat(sendbuf,msg);
	ret = send(listenfd,sendbuf,2048,0);
	if (ret < 0){
		printf("nl80211: NL_SEND_AUTO_COMPLETE failed\n");
		close(listenfd);
	}
	return ret ;
	}
}


int sock_adapt(int type, struct nl_handle *nl_handle, struct nl_msg *msg, struct nl_cb *cb)
{
    switch(type) {
		case NL_SEND_AUTO_COMPLETE:
			return nl_send_auto_complete_apda(nl_handle,msg);
			break;
		case NL_RECVMSGS:
			//if (cb->cb_recvmsgs_ow)
                 	//	return cb->cb_recvmsgs_ow(nl_handle, cb);
			//else
			return nl_recvmsgs_adpa(nl_handle, cb);
			break;
		default:
			break;
    }
	return 0;
}
