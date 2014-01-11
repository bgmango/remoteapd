#
# Makefile for ALL Workspace
#
include ./make.h

TARGETS	 =  agentapd_socket

COMMON_OBJS = agentapd_socket.o
OBJS = $(COMMON_OBJS)
all: $(LIBS) $(TARGETS)

$(TARGETS):$(OBJS)
	$(CC) $(CC_OUTPUT_FLAGS) $(TARGETS) $(OBJS) $(CC_NETLINK_FLAGS)

.c.o:
	$(CC) $(CC_FLAGS)  $(COMMON_INCLUDE_DIRS)  $<

clean:
	$(RM) $(RM_FLAGS) $(OBJS) $(TARGETS)
	$(RM) $(RM_FLAGS) *.lib *.bak *.a *~


