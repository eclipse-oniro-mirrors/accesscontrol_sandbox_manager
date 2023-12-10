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

#include "sandbox_manager_load_callback.h"

#include "sandbox_manager_client.h"
#include "sandbox_manager_log.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerClient"
};

SandboxManagerLoadCallback::SandboxManagerLoadCallback() {}

void SandboxManagerLoadCallback::OnLoadSystemAbilitySuccess(
    int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject)
{
    if (systemAbilityId != ISandboxManager::SA_ID_SANDBOX_MANAGER_SERVICE) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "start systemabilityId is not sandbox_manager!");
        return;
    }

    if (remoteObject == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "remoteObject is null.");
        SandboxManagerClient::GetInstance().FinishStartSAFail();
        return;
    }

    SANDBOXMANAGER_LOG_INFO(LABEL, "Start systemAbilityId: %{public}d success!", systemAbilityId);

    SandboxManagerClient::GetInstance().FinishStartSASuccess(remoteObject);
}

void SandboxManagerLoadCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    if (systemAbilityId != ISandboxManager::SA_ID_SANDBOX_MANAGER_SERVICE) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "start systemabilityId is not sandbox_manager!");
        return;
    }

    SANDBOXMANAGER_LOG_ERROR(LABEL, "Start systemAbilityId: %{public}d failed.", systemAbilityId);

    SandboxManagerClient::GetInstance().FinishStartSAFail();
}

} // SandboxManager
} // AccessControl
} // OHOS