
#ifndef ADAPTER_H
#define ADAPTER_H

#define NL_SEND_AUTO_COMPLETE 1
#define NL_RECVMSGS 2

int adapter_socket_init();
int NL_cb_set(struct nl_cb *cb, enum nl_cb_type type, enum nl_cb_kind kind, nl_recvmsg_msg_cb_t func, void *arg);
int sock_adapt(int type, struct nl_handle *nl_handle, struct nl_msg *msg, struct nl_cb *cb);



#endif
