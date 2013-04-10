/* pcapjs -- adarqui */
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <node.h>
#include <node_buffer.h>
#include <node_version.h>
#include <v8.h>
#include <pcap.h>

using namespace v8;
using namespace node;

#define MAX_PCAP_CHANNELS 12

struct async_req {
	uv_work_t req;
	int input;
	int output;
	Persistent<Function> callback;
};


struct poll_struct {
	Persistent<Function> callback;
	int fd;
	/* pcap fields */
	void * pcap;
	char device[16];
	int datalink;
};


struct datalink_info {
	int datalink;
	int offset;
};

//pcapjs pcap_channels[MAX_PCAP_CHANNELS+1];

/*
 * PCAP: CORE
 */
void init(Handle<Object> exports, Handle<Object> module);
Handle<Value> Open(const Arguments&);
void on_handle_close (uv_handle_t *handle);
void on_fd_event (uv_poll_t* handle, int status, int events);


/*
 * PCAP: MISC
 */
Handle<Value> FindAllDevs(const Arguments&);
Handle<Value> LookupDev(const Arguments&);
Handle<Value> LookupNet(const Arguments&);


/*
 * PCAP: LIBUV
 */
Handle<Value> UvVersion(const Arguments&);
