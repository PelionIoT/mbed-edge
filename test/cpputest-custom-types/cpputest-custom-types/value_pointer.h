#ifndef TEST_TEST_LIB_TEST_LIB_VALUE_POINTER_COMPARATOR_H_
#define TEST_TEST_LIB_TEST_LIB_VALUE_POINTER_COMPARATOR_H_

#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <sstream>
#include <stdint.h>
#include <stdlib.h>
#include <CppUTest/SimpleString.h>
#include <CppUTestExt/MockSupportPlugin.h>
#include <CppUTestExt/MockSupport.h>
#include <CppUTestExt/MockNamedValue.h>

class ValuePointer {
    uint8_t *data;
    uint32_t size;
public:
    ValuePointer()
    {
        data = NULL;
        size = 0;
    }

    ValuePointer(const uint8_t *data, uint32_t size)
    {
        if (data && size > 0) {
            this->data = (uint8_t *) malloc(size);
            memcpy(this->data, data, size);
        } else {
            this->data = NULL;
        }
        this->size = size;
    }

    ~ValuePointer()
    {
        if (data) {
            free(data);
        }
        data = NULL;
    }

    bool operator==(ValuePointer &other)
    {
        if (this->size != other.size) {
            return false;
        }

        for(int i = 0; i < (int)(this->size); i++) {
            if (this->data[i] != other.data[i]) return false;
        }
        return true;
    }

    void copyFrom(ValuePointer &other)
    {
        this->data = (uint8_t*) malloc(other.size);
        memcpy(this->data, other.data, other.size);
        this->size = other.size;
    }

    char *toString()
    {
        std::ostringstream address;
        int i;
        if (this->data) {
            address << "size: " << this->size << " data: '";
            for(i=0; i < (int)(this->size); i++) {
                // address << "[" << std::hex << (int)(this->data[i]) << "]";
                address << (char) (this->data[i]);
            }
            address << "'";
        } else {
            return strdup("No data in value pointer.");
        }
        return strdup(address.str().c_str());
    }
};

class ValuePointerCopier: public MockNamedValueCopier {
public:
    virtual void copy(void* out, const void* in)
    {
        ((ValuePointer *) out)->copyFrom(*((ValuePointer *) in));
    }
};

class ValuePointerComparator: public MockNamedValueComparator {
public:
    virtual bool isEqual(const void* object1, const void* object2)
    {
        ValuePointer *frame1 = (ValuePointer *)(object1);
        ValuePointer *frame2 = (ValuePointer *)(object2);
        return (*frame1 == *frame2);
    }

    SimpleString valueToString(const void *object)
    {
        ValuePointer *value_pointer = (ValuePointer*)object;
        char* str = value_pointer->toString();
        SimpleString ret = SimpleString(str);
        free(str);
        return ret;
    }
};


#endif /* TEST_TEST_LIB_TEST_LIB_VALUE_POINTER_COMPARATOR_H_ */
