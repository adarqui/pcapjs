/* pcapjs -- adarqui */
#include "pcap.h"


void on_handle_close (uv_handle_t *handle) {
	delete handle;
}


/* the "on fd IO event" callback; called on the main thread */
void on_fd_event (uv_poll_t* handle, int status, int events) {
	HandleScope scope;

	poll_struct *m = (poll_struct *) handle->data;

	const unsigned char * data;
	struct pcap_pkthdr phdr;
 
	/* Some code here that works with `fd` (and closes it if needed) and produces `Handle<Value> result` */
	data = pcap_next((pcap_t*)m->pcap, &phdr);

	Handle<Value> argv[1];

	Local<Object> packet_header = Object::New();
	
	packet_header->Set(String::New("if"), String::New(m->device));
	packet_header->Set(String::New("datalink"), Integer::NewFromUnsigned(m->datalink));
	packet_header->Set(String::New("tv_sec"), Integer::NewFromUnsigned(phdr.ts.tv_sec));
	packet_header->Set(String::New("tv_usec"), Integer::NewFromUnsigned(phdr.ts.tv_usec));
	packet_header->Set(String::New("caplen"), Integer::NewFromUnsigned(phdr.caplen));
	packet_header->Set(String::New("len"), Integer::NewFromUnsigned(phdr.len));

	Local<Array> packet = Array::New(phdr.caplen);

	size_t i;
	for(i=0;i<phdr.caplen;i++) {
		packet->Set(i, Number::New(data[i]));
	}

	Local<Object> result = Object::New();
	result->Set(String::New("hdr"), packet_header);
	result->Set(String::New("pkt"), packet);

	argv[0] = result;

	TryCatch try_catch;
	m->callback->Call(Context::GetCurrent()->Global(), 1, argv);

	if (try_catch.HasCaught())
		FatalException(try_catch);
}



Handle<Value> Open(const Arguments& args) {
	/*
	 * var po = pcap.open(dev, filter, snaplen, to_ms, callback)
	 */
	HandleScope scope;
	char errbuf[PCAP_ERRBUF_SIZE];
	int snaplen = 65535, to_ms = 1000;

	struct bpf_program fp;	

	bpf_u_int32 mask;
	bpf_u_int32 net;

	int datalink;

	if(args.Length() == 5) {
		if(!args[0]->IsString()) {
			return ThrowException(Exception::TypeError(String::New("Open: Incorrect device")));
		}
		if(!args[1]->IsString()) {
			return ThrowException(Exception::TypeError(String::New("Open: Incorrect filter")));
		}
		if(!args[2]->IsInt32()) {
		}
		if(!args[3]->IsInt32()) {
		}

		String::Utf8Value device(args[0]->ToString());
		String::Utf8Value filter(args[1]->ToString());

		if(!strcasecmp(*device, "any") || !strcasecmp(*device, "all")) {
			return ThrowException(Exception::TypeError(String::New("Open: Don't use any or all")));
		}

		snaplen = args[2]->Int32Value();
		to_ms = args[3]->Int32Value();


		if (pcap_lookupnet(*device, &net, &mask, errbuf) == -1) {
			net = 0;
			mask = 0;
		}

		void * handle = pcap_open_live((const char *)*device, BUFSIZ, 1, 1000, errbuf);

		if(!handle) {
			return ThrowException(Exception::TypeError(String::New("pcap_open_live: Failed")));
		}


		datalink = pcap_datalink((pcap_t*)handle);
		if(datalink == -1) {
			return ThrowException(Exception::TypeError(String::New("pcap_datalink: Failed")));
		}
		

		if(!*filter || (!strncasecmp(*filter, "none", 4)||!strncasecmp(*filter, "all", 3)||!strncasecmp(*filter,"none",4))) {
		}
		else {

			if (pcap_compile((pcap_t*)handle, &fp, *filter, 0, 0) == -1) {
				return ThrowException(Exception::TypeError(String::New(pcap_geterr((pcap_t*)handle))));
		}
			if (pcap_setfilter((pcap_t*)handle, &fp) == -1) {
				return ThrowException(Exception::TypeError(String::New(pcap_geterr((pcap_t*)handle))));
			}
		}


		int fd = pcap_get_selectable_fd((pcap_t*)handle);

		int err=0;

		poll_struct *m = new poll_struct;
		m->fd = fd;
		m->callback = Persistent<Function>::New(Local<Function>::Cast(args[4]));
		m->pcap = (pcap_t*)handle;
		m->datalink = datalink;
		snprintf(m->device, sizeof(m->device)-1, "%s", *device);

		uv_poll_t* _handle = new uv_poll_t;
		_handle->data = m;
		err =   uv_poll_init(uv_default_loop(), _handle, fd);
		err=  uv_poll_start(_handle, UV_READABLE /* or other flags */, on_fd_event);
	}
	
	return scope.Close(Integer::New(1));
}


void init(Handle<Object> exports, Handle<Object> module) {
	
	NODE_SET_METHOD(exports, "lookupDev", LookupDev);
	NODE_SET_METHOD(exports, "findAllDevs", FindAllDevs);
	NODE_SET_METHOD(exports, "open", Open);

	NODE_SET_METHOD(exports, "uvVersion", UvVersion);
}

NODE_MODULE(pcap, init)
