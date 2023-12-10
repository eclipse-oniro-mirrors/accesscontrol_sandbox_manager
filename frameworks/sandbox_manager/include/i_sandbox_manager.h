/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef I_SANDBOX_MANAGER_H
#define I_SANDBOX_MANAGER_H
#include <vector>
#include "errors.h"
#include "iremote_broker.h"
#include "policy_info.h"
#include "sandboxmanager_service_ipc_interface_code.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class ISandboxManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accesscontrol.sandbox_manager.ISandboxManager");

    static const int SA_ID_SANDBOX_MANAGER_SERVICE = SANDBOX_MANAGER_SERVICE_ID;

    virtual int32_t persistPermission(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) = 0;
    virtual int32_t unPersistPermission(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) = 0;
    virtual int32_t setPolicy(uint64_t tokenid, const std::vector<PolicyInfo> &policy, uint64_t policyFlag) = 0;
    virtual int32_t startAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) = 0;
    virtual int32_t stopAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) = 0;
    virtual int32_t checkPersistPermission(
        uint64_t tokenid, const std::vector<PolicyInfo> &policy, std::vector<bool> &result) = 0;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS

#endif // I_SANDBOX_MANAGER_H