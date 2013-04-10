#include "pcap.h"

Handle<Value> FindAllDevs(const Arguments& args) {
    HandleScope scope;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *cur_dev;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
        return ThrowException(Exception::TypeError(String::New(errbuf)));
    }

    Local<Array> DevsArray = Array::New();

    int i=0;
    for (cur_dev = alldevs ; cur_dev != NULL ; cur_dev = cur_dev->next, i++) {
        Local<Object> Dev = Object::New();

        Dev->Set(String::New("name"), String::New(cur_dev->name));
        if (cur_dev->description != NULL) {
            Dev->Set(String::New("description"), String::New(cur_dev->description));
        }

        DevsArray->Set(Integer::New(i), Dev);
    }

    return scope.Close(DevsArray);
}



Handle<Value> LookupDev(const Arguments& args) {
    HandleScope scope;
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        return ThrowException(Exception::TypeError(String::New(errbuf)));
    }

    return scope.Close(String::New(dev));
}




Handle<Value>LookupNet(const Arguments& args) {
    HandleScope scope;

    return scope.Close(String::New("bleh"));
}




