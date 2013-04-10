#include "pcap.h"

Handle<Value> UvVersion(const Arguments& args) {
    HandleScope scope;
    const char * ver = "version";

    return scope.Close(String::New(ver));
}
