#ifndef TESTFACTORY_H
#define TESTFACTORY_H

#include <string.h>
#include <stdio.h>

#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#include "edge-client/edge_client.h"
#include "mbed-client/m2mendpoint.h"
#include "mbed-client/m2mobject.h"
#include "pal.h"


class TestFactory {
public:
  static M2MEndpoint *create_endpoint(String &name, char *path);
  static M2MObject *create_object(String &name, char *path, bool external_blockwise_store);
  static M2MObjectInstance *create_object_instance(M2MObject &parent);
  static M2MResource *create_resource(M2MObjectInstance &parent, String &resource_name, char *path, bool multiple_instance, bool external_blockwise_store);
  static void delete_resource(M2MResource *resource) { delete resource; }
  static void delete_object_instance(M2MObjectInstance *object_instance) { delete object_instance; }
  static void delete_object(M2MObject *object) { delete object; }
};

#endif


