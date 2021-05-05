#include "testfactory.h"
#include "m2mobject.h"
#include "m2mendpoint.h"
#include "m2mresource.h"

M2MEndpoint * TestFactory::create_endpoint(String &name, char *path)
{
    return new M2MEndpoint(name, path);
}

M2MObject* TestFactory::create_object(String &name, char *path, bool external_blockwise_store)
{
    return new M2MObject(name, path, external_blockwise_store);
}

M2MObjectInstance *TestFactory::create_object_instance(M2MObject& parent)
{
    return new M2MObjectInstance(parent, "", NULL);
}

M2MResource *TestFactory::create_resource(M2MObjectInstance &parent, String &resource_name, char *path, bool multiple_instance, bool external_blockwise_store)
{
    return new M2MResource(parent, resource_name, M2MBase::Dynamic, "", M2MBase::OPAQUE,
                                  false /* observable */, path,
                                  multiple_instance, external_blockwise_store);
}

