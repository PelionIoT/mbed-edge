#ifndef JSON_MESSAGE_T_POINTER_H_
#define JSON_MESSAGE_T_POINTER_H_

#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <sstream>

#include "jansson.h"
#include "edge-rpc/rpc.h"

class JsonMessageTPointer {
    char *data = NULL;
    size_t size;
    struct connection *connection;


public:
    JsonMessageTPointer(char *data, size_t len, struct connection *connection) {
        this->data = data;
        this->size = len;
        this->connection = connection;
    }

    ~JsonMessageTPointer() {
    }

    bool operator==(JsonMessageTPointer &other) {
        if (this->size != other.size) {
            return false;
        }
        if (this->connection != other.connection) {
            return false;
        }
        if (strncmp(data, other.data, this->size) != 0) {
            return false;
        }
        return true;
    }

    void copyFrom(JsonMessageTPointer &other) {
        if (this->data) free(this->data);
        this->data = (char*) malloc(other.size);
        memcpy(this->data, other.data, other.size);
        this->size = other.size;
        this->connection = other.connection;
    }

    char *toString() {
        std::ostringstream obj_repr;
        obj_repr << "data: \"" << this->data << "\" | size: " << this->size \
                 << " | connection_addr: " << std::hex << static_cast<const void*>(this->connection) << std::endl;
        return strdup(obj_repr.str().c_str());
    }
};

class JsonMessageTPointerCopier: public MockNamedValueCopier {
public:
    virtual void copy(void *out, const void *in) {
        ((JsonMessageTPointer *) out)->copyFrom(*((JsonMessageTPointer *) in));
    }
};

class JsonMessageTPointerComparator: public MockNamedValueComparator {
public:
    virtual bool isEqual(const void *object1, const void *object2) {
        JsonMessageTPointer *jmtp1 = (JsonMessageTPointer*) object1;
        JsonMessageTPointer *jmtp2 = (JsonMessageTPointer*) object2;
        return (*jmtp1 == *jmtp2);
    }

    SimpleString valueToString(const void *object) {
        JsonMessageTPointer *jmtp = (JsonMessageTPointer*) object;
        char *str = jmtp->toString();
        SimpleString ret = SimpleString(str);
        free(str);
        return ret;
    }
};

#endif // JSON_MESSAGE_T_POINTER_H_
