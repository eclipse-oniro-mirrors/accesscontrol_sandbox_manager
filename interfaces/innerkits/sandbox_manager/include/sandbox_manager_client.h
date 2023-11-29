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

/**
* @addtogroup
* @{
*
* @brief
*
* @since
* @version
*/

#ifndef SANDBOXMANAGER_CLIENT_H
#define SANDBOXMANAGER_CLIENT_H

#include "i_sandbox_manager.h"
#include "refbase.h"
#include "nocopyable.h"
#include "policy_info.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class SandboxManagerClient final {
public:
    static SandboxManagerClient& GetInstance();
    virtual ~SandboxManagerClient();

    int persistPermission(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    int unPersistPermission(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    int setPolicy(uint64_t tokenid, const std::vector<PolicyInfo> &policy, uint64_t policyFlag);
    int startAccessingURI(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    int stopAccessingURI(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    int checkPersistPermission(uint64_t tokenid, const std::vector<PolicyInfo> &policy, std::vector<bool> &result);

private:
    SandboxManagerClient();
    DISALLOW_COPY_AND_MOVE(SandboxManagerClient);
    sptr<ISandboxManager> proxy_ = nullptr;
};
} // SandboxManager
} // AccessControl
} // OHOS
#endif //SANDBOXMANAGER_CLIENT_H