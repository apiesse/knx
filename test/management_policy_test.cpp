#include "knx/management_policy.h"
#include "knx/property.h"

using namespace KnxManagementPolicy;

static_assert(accessLevel(true) == 0, "programming mode must grant level 0");
static_assert(accessLevel(false) == 3, "normal operation must remain least privileged");
static_assert(memoryAccessAllowed(true), "physical programming mode permits management memory");
static_assert(!memoryAccessAllowed(false), "raw management memory must fail closed");

static_assert(readAllowed(ReadLv3 | WriteLv3, false), "level-3 reads remain public");
static_assert(!readAllowed(ReadLv0 | WriteLv3, false), "privileged reads fail closed");
static_assert(readAllowed(ReadLv0 | WriteLv0, true), "programming mode permits privileged reads");

static_assert(!writeAllowed(ReadLv3 | WriteLv3, false), "writes require programming mode");
static_assert(!writeAllowed(ReadLv0 | WriteLv0, false), "level-0 writes also require programming mode");
static_assert(writeAllowed(ReadLv3 | WriteLv3, true), "programming mode permits level-3 writes");
static_assert(writeAllowed(ReadLv0 | WriteLv0, true), "programming mode permits level-0 writes");

// Compile-only translation unit: all policy expectations are checked above.
void managementPolicyCompileAnchor() {}
