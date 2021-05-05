#ifndef TEST_LIB_EDGECLIENT_REQUEST_CONTEXT_COMPARATOR_H_
#define TEST_LIB_EDGECLIENT_REQUEST_CONTEXT_COMPARATOR_H_

#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <sstream>
#include <stdint.h>

class EdgeClientRequestContext {
    char* device_id;
    uint16_t object_id;
    uint16_t object_instance_id;
    uint16_t resource_id;
    uint8_t *value;
    uint32_t value_len;
    uint8_t *token;
    uint8_t token_len;
    uint8_t operation;
    void *success_handler;
    void *failure_handler;
    void *userdata;
public:
    EdgeClientRequestContext()
    {
        device_id = NULL;
        object_id = 999;
        object_instance_id = 999;
        resource_id = 999;
        value = NULL;
        value_len = 0;
        token = NULL;
        token_len = 0;
        operation = 0;
        success_handler = NULL;
        failure_handler = NULL;
        userdata = NULL;
    }

    EdgeClientRequestContext(const char *device_id,
                             uint16_t object_id,
                             uint16_t object_instance_id,
                             uint16_t resource_id,
                             const uint8_t *value,
                             uint32_t value_len,
                             const uint8_t *token,
                             uint8_t token_len,
                             uint8_t operation,
                             void *success_handler,
                             void *failure_handler,
                             void *userdata)
    {
        if (value && value_len > 0) {
            this->value = (uint8_t *) malloc(value_len);
            memcpy(this->value, value, value_len);
        } else {
            this->value = NULL;
        }
        this->value_len = value_len;
        if (token && token_len > 0) {
            this->token = (uint8_t *) malloc(token_len);
            memcpy(this->token, token, token_len);
        } else {
            this->token = NULL;
        }
        this->token_len = token_len;
        if (device_id) {
            this->device_id = strdup(device_id);
        } else {
            this->device_id = NULL;
        }
        this->object_id = object_id;
        this->object_instance_id = object_instance_id;
        this->resource_id = resource_id;
        this->operation = operation;
        this->success_handler = success_handler;
        this->failure_handler = failure_handler;
        this->userdata = userdata;
    }

    ~EdgeClientRequestContext()
    {
        if (value) {
            free(value);
        }
        free(token);
        free(device_id);
        value = NULL;
    }

    bool operator==(EdgeClientRequestContext &other)
    {
        if (this->value_len != other.value_len) {
            return false;
        }

        for (int i = 0; i < (int)(this->value_len); i++) {
            if (this->value[i] != other.value[i]) return false;
        }

        if (this->token_len != other.token_len) {
            return false;
        }

        for (int i = 0; i < (int) (this->token_len); i++) {
            if (this->token[i] != other.token[i])
                return false;
        }

        if (strlen(this->device_id) != strlen(other.device_id) ||
            strncmp(this->device_id, other.device_id, strlen(this->device_id)) != 0) {
            return false;
        }

        if (this->object_id != other.object_id ||
            this->object_instance_id != other.object_instance_id ||
            this->resource_id != other.resource_id) {
            return false;
        }

        if (this->operation != other.operation) {
            return false;
        }

        if (this->userdata != other.userdata) {
            return false;
        }

        return true;
    }

    void copyFrom(EdgeClientRequestContext &other)
    {
        this->value = (uint8_t*) malloc(other.value_len);
        memcpy(this->value, other.value, other.value_len);
        this->value_len = other.value_len;

        this->token = (uint8_t *) malloc(other.token_len);
        memcpy(this->token, other.token, other.token_len);
        this->token_len = other.token_len;

        this->device_id = (char*) calloc(strlen(other.device_id), sizeof(char));
        strncpy(this->device_id, other.device_id, strlen(other.device_id));

        this->object_id = other.object_id;
        this->object_instance_id = other.object_instance_id;
        this->resource_id = other.resource_id;

        this->operation = other.operation;
        this->success_handler = other.success_handler;
        this->failure_handler = other.failure_handler;
        this->userdata = other.userdata;
    }

    char *toString()
    {
        std::ostringstream address;
        address << "device_id: " << this->device_id;
        address << " | object_id: " << this->object_id;
        address << " | object_instance_id: " << this->object_instance_id;
        address << " | resource_id: " << this->resource_id;
        address << " | operation: " << this->operation;
        address << " | value_len: " << this->value_len;
        address << " | token_len: " << this->token_len;
        address << " | userdata: " << this->userdata;
        address << " | value: ";
        int i;
        if (this->value) {
            for(i=0; i < (int)(this->value_len); i++) {
                address << "[" << std::hex << (int)(this->value[i]) << "]";
            }
        } else {
            return strdup("No data in value field.");
        }
        address << " | token: ";
        if (this->token) {
            for (i = 0; i < (int) (this->token_len); i++) {
                address << "[" << std::hex << (int) (this->token[i]) << "]";
            }
        } else {
            return strdup("No data in token field.");
        }
        return strdup(address.str().c_str());
    }
};

class EdgeClientRequestContextCopier: public MockNamedValueCopier {
public:
    virtual void copy(void* out, const void* in)
    {
        ((EdgeClientRequestContext *) out)->copyFrom(*((EdgeClientRequestContext *) in));
    }
};

class EdgeClientRequestContextComparator: public MockNamedValueComparator {
public:
    virtual bool isEqual(const void* object1, const void* object2)
    {
        EdgeClientRequestContext *frame1 = (EdgeClientRequestContext *)(object1);
        EdgeClientRequestContext *frame2 = (EdgeClientRequestContext *)(object2);
        return (*frame1 == *frame2);
    }

    SimpleString valueToString(const void *object)
    {
        EdgeClientRequestContext *write_ctx = (EdgeClientRequestContext*)object;
        char* str = write_ctx->toString();
        SimpleString ret = SimpleString(str);
        free(str);
        return ret;
    }
};


#endif /* TEST_LIB_EDGECLIENT_REQUEST_CONTEXT_COMPARATOR_H_ */
