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

#ifndef SANDBOXMANAGER_KIT_H
#define SANDBOXMANAGER_KIT_H

#include "policy_info.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
/**
 * @brief Declares SandboxManagerKit class
 */
class SandboxManagerKit {
public:
    static int32_t persistPermission(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    static int32_t unPersistPermission(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    static int32_t setPolicy(uint64_t tokenid, const std::vector<PolicyInfo> &policy, uint64_t policyFlag);
    static int32_t startAccessingURI(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    static int32_t stopAccessingURI(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    static int32_t checkPersistPermission(
        uint64_t tokenid, const std::vector<PolicyInfo> &policy, std::vector<bool> &result);
};
} // SandboxManager
} // AccessControl
} // OHOS
#endif //SANDBOXMANAGER_KIT_H