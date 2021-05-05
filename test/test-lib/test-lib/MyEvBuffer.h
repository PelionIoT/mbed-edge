#ifndef MY_EV_BUFFER_H
#define MY_EV_BUFFER_H

#include <event2/buffer.h>
#include <string.h>
#include <assert.h>
#include <jansson.h>

// This class makes it easier to test if content of evbuffer matches
// to what is expected.
class MyEvBuffer {
public:
    size_t buffer_size;
    uint8_t *buffer;

private:

    void setString(char *string)
    {
        assert(buffer == NULL);
        if (string) {
            buffer = (uint8_t *)strdup(string);
            buffer_size = strlen(string);
        }
    }

public:
    MyEvBuffer()
    {
        buffer = NULL;
    }

    MyEvBuffer(const char *string)
    {
        buffer = NULL;
        setString((char *) string);
    }

    virtual ~MyEvBuffer()
    {
        if (buffer) {
            free(buffer);
            buffer = NULL;
        }
    }

    void copyFrom(MyEvBuffer &buf2)
    {
        if (buffer) {
            free(buffer);
            buffer = NULL;
        }
        setString((char *) buf2.buffer);
    }

    /* returns the buffer that needs to be freed using free() */
    char *copyOut()
    {
        return strdup((char *) buffer);
    }
};

class MyEvBufferCopier: public MockNamedValueCopier {
public:
    virtual void copy(void* out, const void* in)
    {
        ((MyEvBuffer *) out)->copyFrom(*((MyEvBuffer *) in));
    }
};

class MyEvBufferComparator: public MockNamedValueComparator {
public:
    virtual bool isEqual(const void* object1, const void* object2)
    {
        MyEvBuffer *buf1 = (MyEvBuffer *) object1;
        MyEvBuffer *buf2 = (MyEvBuffer *) object2;
        if (buf1->buffer_size != buf2->buffer_size) {
            return false;
        }
        int rc = memcmp(buf1->buffer, buf2->buffer, buf1->buffer_size);
        return rc == 0;
    }

    virtual SimpleString valueToString(const void* object)
    {
        MyEvBuffer *evBuffer = (MyEvBuffer *) object;
        char *out = evBuffer->copyOut();
        SimpleString result = SimpleString(out);
        free(out);
        return result;
    }
};
#endif
