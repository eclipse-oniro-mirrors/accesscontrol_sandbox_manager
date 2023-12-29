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

#include <cstddef>
#include <cstdint>
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "package_uninstall_observer.h"
#include "policy_info_manager.h"
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

int32_t SandboxManagerService::PersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "policy vector size error: %{public}lu", policy.size());
        return INVALID_PARAMTER;
    }
    result.resize(policySize);
    return PolicyInfoManager::GetInstance().AddPolicy(callingTokenId, policy, result);
}

int32_t SandboxManagerService::UnPersistPolicy(
    const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "policy vector size error: %{public}lu", policy.size());
        return INVALID_PARAMTER;
    }

    result.resize(policySize);
    return PolicyInfoManager::GetInstance().RemovePolicy(callingTokenId, policy, result);
}

int32_t SandboxManagerService::PersistPolicyByTokenId(
    uint64_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    size_t policySize = policy.size();
    if ((policySize == 0) || (policySize > POLICY_VECTOR_SIZE_LIMIT) || (tokenId == 0)) {
        SANDBOXMANAGER_LOG_ERROR(
            LABEL, "policy vector size error: %{public}lu, tokenid is %{public}lu", policy.size(), tokenId);
        return INVALID_PARAMTER;
    }
    result.resize(policySize);
    return PolicyInfoManager::GetInstance().AddPolicy(tokenId, policy, result);
}

int32_t SandboxManagerService::UnPersistPolicyByTokenId(
    uint64_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    size_t policySize = policy.size();
    if ((policySize == 0) || (policySize > POLICY_VECTOR_SIZE_LIMIT) || (tokenId == 0)) {
        SANDBOXMANAGER_LOG_ERROR(
            LABEL, "policy vector size error: %{public}lu, tokenid is %{public}lu", policy.size(), tokenId);
        return INVALID_PARAMTER;
    }

    result.resize(policySize);
    return PolicyInfoManager::GetInstance().RemovePolicy(tokenId, policy, result);
}

int32_t SandboxManagerService::SetPolicy(uint64_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag)
{
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "policy vector size error: %{public}lu", policy.size());
        return INVALID_PARAMTER;
    }

    if (policyFlag == IS_POLICY_ALLOWED_TO_BE_PRESISTED) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Allow to set persistant");
    } else {
        SANDBOXMANAGER_LOG_INFO(LABEL, "NOT allow to set persistant");
    }
    // set to Mac here, FORBIDDEN_TO_BE_PERSISTED
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::StartAccessingPolicy(
    const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "policy vector size error: %{public}lu", policy.size());
        return INVALID_PARAMTER;
    }

    std::vector<uint32_t> matchResult(policy.size());

    int32_t ret = PolicyInfoManager::GetInstance().MatchPolicy(callingTokenId, policy, matchResult);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    // setURI here
    result = matchResult;
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::StopAccessingPolicy(
    const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "policy vector size error: %{public}lu", policy.size());
        return INVALID_PARAMTER;
    }

    std::vector<uint32_t> matchResult(policy.size());
    int32_t ret = PolicyInfoManager::GetInstance().MatchPolicy(callingTokenId, policy, matchResult);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    // stopURI here
    result = matchResult;
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerService::CheckPersistPolicy(
    uint64_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result)
{
    size_t policySize = policy.size();
    if (policySize == 0 || policySize > POLICY_VECTOR_SIZE_LIMIT) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "policy vector size error: %{public}lu", policy.size());
        return INVALID_PARAMTER;
    }

    std::vector<uint32_t> matchResult(policySize);

    int32_t ret = PolicyInfoManager::GetInstance().MatchPolicy(tokenId, policy, matchResult);
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    result.resize(policySize);
    for (size_t i = 0; i < policy.size(); i++) {
        result[i] = (matchResult[i] == OPERATE_SUCCESSFULLY);
    }
    return SANDBOX_MANAGER_OK;
}

bool SandboxManagerService::Initialize()
{
    DelayUnloadService();
    SubscribeUninstallEvent();
    PolicyInfoManager::GetInstance().Init();
    return true;
}

void SandboxManagerService::SubscribeUninstallEvent()
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto pkgUninstallObserver = std::make_shared<PkgUninstallObserver>(subscribeInfo);
    if (EventFwk::CommonEventManager::SubscribeCommonEvent(pkgUninstallObserver)) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "regist common event");
    } else {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "regist common event error");
    }
    return;
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
    };
    unloadHandler_->RemoveTask("SandboxManagerUnload");
    unloadHandler_->PostTask(task, "SandboxManagerUnload", SA_LIFE_TIME);
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS