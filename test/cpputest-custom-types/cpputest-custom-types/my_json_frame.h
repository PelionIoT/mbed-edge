
#include <jansson.h>
#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#include <CppUTest/SimpleString.h>
#include <CppUTestExt/MockSupportPlugin.h>
#include <CppUTestExt/MockSupport.h>
#include <CppUTestExt/MockNamedValue.h>

class MyJsonFrame {
    json_t *tree;
    uint32_t expected_size;
public:
    MyJsonFrame()
    {
        tree = NULL;
        expected_size = 0;
    }

    MyJsonFrame(const char *data)
    {
        this->expected_size = strlen(data);
        json_error_t error;
        tree = json_loadb(data, this->expected_size, 0, &error);
        assert(tree);
    }

    MyJsonFrame(const char *data, size_t expected_size) {
        this->expected_size = expected_size;
        json_error_t error;
        tree = json_loadb(data, this->expected_size, 0, &error);
        assert(tree);
    }

    MyJsonFrame(json_t *data) {
        this->tree = data;
    }

    ~MyJsonFrame()
    {
        json_decref(tree);
    }

    bool operator==(MyJsonFrame &other)
    {
        if (this->expected_size && this->expected_size != other.expected_size) {
            return false;
        }
        return json_equal(tree, other.tree);
    }

    void copyFrom(MyJsonFrame &frame)
    {
        if (tree) {
            json_decref(tree);
        }
        tree = json_deep_copy(frame.tree);
    }
    char *toString()
    {
        return json_dumps(tree, JSON_COMPACT | JSON_SORT_KEYS);
    }
};

class MyJsonFrameCopier: public MockNamedValueCopier {
public:
    virtual void copy(void* out, const void* in)
    {
        ((MyJsonFrame *) out)->copyFrom(*((MyJsonFrame *) in));
    }
};

class MyJsonFrameComparator: public MockNamedValueComparator {
public:
    virtual bool isEqual(const void* object1, const void* object2)
    {
        MyJsonFrame *frame1 = (MyJsonFrame *)(object1);
        MyJsonFrame *frame2 = (MyJsonFrame *)(object2);
        return (*frame1 == *frame2);
    }

    SimpleString valueToString(const void *object)
    {
        MyJsonFrame *frame = (MyJsonFrame*)object;
        char *str = frame->toString();
        SimpleString ret = SimpleString(str);
        free(str);
        return ret;
    }
};
