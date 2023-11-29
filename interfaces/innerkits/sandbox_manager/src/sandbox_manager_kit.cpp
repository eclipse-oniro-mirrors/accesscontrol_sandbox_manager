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


#include "sandbox_manager_client.h"
#include "sandbox_manager_kit.h"
#include "sandbox_manager_log.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxMngKit"};
}

int SandboxManagerKit::persistPermission(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    return SandboxManagerClient::GetInstance().persistPermission(policy, result);
}

int SandboxManagerKit::unPersistPermission(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    return SandboxManagerClient::GetInstance().unPersistPermission(policy, result);
}

int SandboxManagerKit::setPolicy(uint64_t tokenid, const std::vector<PolicyInfo> &policy, uint64_t policyFlag)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    return SandboxManagerClient::GetInstance().setPolicy(tokenid, policy, policyFlag);
}

int SandboxManagerKit::startAccessingURI(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    return SandboxManagerClient::GetInstance().startAccessingURI(policy, result);
}

int SandboxManagerKit::stopAccessingURI(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    return SandboxManagerClient::GetInstance().stopAccessingURI(policy, result);
}

int SandboxManagerKit::checkPersistPermission(
    uint64_t tokenid, const std::vector<PolicyInfo> &policy, std::vector<bool> &result)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "called");
    return SandboxManagerClient::GetInstance().checkPersistPermission(tokenid, policy, result);
}

} // SandboxManager
} // AccessControl
} // OHOS