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

#include "sandbox_manager_service.h"

#include <sys/types.h>
#include <unistd.h>
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
using namespace OHOS::AppExecFwk;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerService"
};
}

REGISTER_SYSTEM_ABILITY_BY_ID(SandboxManagerService,
    SandboxManagerService::SA_ID_SANDBOX_MANAGER_SERVICE, true);


SandboxManagerService::SandboxManagerService(int saId, bool runOnCreate)
    : SystemAbility(saId, runOnCreate), state_(ServiceRunningState::STATE_NOT_START)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService()");
}

SandboxManagerService::SandboxManagerService()
    : SystemAbility(SA_ID_SANDBOX_MANAGER_SERVICE, true), state_(ServiceRunningState::STATE_NOT_START)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService()");
}

SandboxManagerService::~SandboxManagerService()
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "~SandboxManagerService()");
}

void SandboxManagerService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService has already started!");
        return;
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "SandboxManagerService is starting");
    if (!Initialize()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to initialize ");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    bool ret = Publish(DelayedSingleton<SandboxManagerService>::GetInstance().get());
    if (!ret) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Failed to publish service! ");
        return;
    }
    SANDBOXMANAGER_LOG_INFO(LABEL, "Congratulations, SandboxManagerService start successfully!");
}

void SandboxManagerService::OnStop()
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "stop sandbox manager service");
    state_ = ServiceRunningState::STATE_NOT_START;
}

int32_t SandboxManagerService::persistPermission(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    result.resize(policy.size());
    return 0;
}

int32_t SandboxManagerService::unPersistPermission(
    const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    result.resize(policy.size());
    return 0;
}

int32_t SandboxManagerService::setPolicy(uint64_t tokenid, const std::vector<PolicyInfo> &policy, uint64_t policyFlag)
{
    return 0;
}

int32_t SandboxManagerService::startAccessingPolicy(
    const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    result.resize(policy.size());
    return 0;
}

int32_t SandboxManagerService::stopAccessingPolicy(
    const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    result.resize(policy.size());
    return 0;
}

int32_t SandboxManagerService::checkPersistPermission(
    uint64_t tokenid, const std::vector<PolicyInfo> &policy, std::vector<bool> &result)
{
    result.resize(policy.size());
    return 0;
}

bool SandboxManagerService::Initialize()
{
    DelayUnloadService();
    return true;
}

void SandboxManagerService::DelayUnloadService()
{
    if (unloadHandler_ == nullptr) {
        std::shared_ptr<EventRunner> runner
            = EventRunner::Create(SA_ID_SANDBOX_MANAGER_SERVICE);
        unloadHandler_ = std::make_shared<EventHandler>(runner);
    }

    auto task = [this]() {
        auto samgrProxy = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "get samgr failed");
            return;
        }
        int32_t ret = samgrProxy->UnloadSystemAbility(SA_ID_SANDBOX_MANAGER_SERVICE);
        if (ret != ERR_OK) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "unload system ability failed");
            return;
        }
        SANDBOXMANAGER_LOG_DEBUG(LABEL, "unload service succ");
    };
    unloadHandler_->RemoveTask("SandboxManagerUnload");
    unloadHandler_->PostTask(task, "SandboxManagerUnload", SA_LIFE_TIME);
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
