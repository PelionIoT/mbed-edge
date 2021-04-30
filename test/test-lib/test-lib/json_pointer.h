#ifndef TEST_TEST_LIB_TEST_LIB_JSON_POINTER_COMPARATOR_H_
#define TEST_TEST_LIB_TEST_LIB_JSON_POINTER_COMPARATOR_H_

#include <assert.h>
#include <string.h>
#include <stddef.h>
#include "jansson.h"

class JsonPointer {
    json_t *tree;
    bool copied;
public:
    JsonPointer()
    {
        tree = NULL;
        copied = false;
    }

    JsonPointer(json_t *tree)
    {
        this->tree = tree;
        copied = false;
    }

    ~JsonPointer()
    {
        // Do not free `tree` unless it is copied
        // the deallocation is handled in production code or test code for original tree
        if (copied) {
            json_decref(this->tree);
        }
    }

    void free_tree() {
        json_decref(tree);
    }

    bool operator==(JsonPointer &other)
    {
        // Both NULL
        if (!this->tree && !other.tree) {
            return true;
        }
        // Same pointer
        if (this->tree == other.tree) {
            return true;
        }
        if (this->tree) {
            return json_equal(this->tree, other.tree);
        } else {
            return false;
        }
    }

    void copyFrom(JsonPointer &other)
    {
        // do not decref original tree
        // it is handled by production code or test code
        // flag the decref of copied tree for delete
        this->copied = true;

        if (other.tree) {
            this->tree = json_deep_copy(other.tree);
        } else {
            this->tree = NULL;
        }
    }

    char *toString()
    {
        if (this->tree) {
            return json_dumps(this->tree, JSON_COMPACT);
        } else {
            char *str = (char*) calloc(strlen("empty pointer") + 1, sizeof(char));
            memcpy(str, "empty pointer", strlen("empty pointer"));
            return str;
        }
    }
};

class JsonPointerCopier: public MockNamedValueCopier {
public:
    void copy(void* out, const void* in)
    {
        ((JsonPointer *) out)->copyFrom(*((JsonPointer *) in));
    }
};

class JsonPointerComparator: public MockNamedValueComparator {
public:
    virtual bool isEqual(const void* object1, const void* object2)
    {
        JsonPointer *json1 = (JsonPointer *)(object1);
        JsonPointer *json2 = (JsonPointer *)(object2);
        return (*json1 == *json2);
    }

    SimpleString valueToString(const void *object)
    {
        JsonPointer *json_pointer = (JsonPointer*)object;
        char* str = json_pointer->toString();
        SimpleString ret = SimpleString(str);
        free(str);
        return ret;
    }
};


#endif /* TEST_TEST_LIB_TEST_LIB_JSON_POINTER_COMPARATOR_H_ */
