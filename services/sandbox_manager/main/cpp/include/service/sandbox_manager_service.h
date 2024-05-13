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

#ifndef SANDBOX_MANAGER_SERVICE_H
#define SANDBOX_MANAGER_SERVICE_H
#include <cstdint>
#include <string>
#include <vector>
#include "event_handler.h"
#include "iremote_object.h"
#include <mutex>
#include "nocopyable.h"
#include "sandbox_manager_stub.h"
#include "singleton.h"
#include "system_ability.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
using namespace OHOS::AppExecFwk;
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
class SandboxManagerService final : public SystemAbility, public SandboxManagerStub {
    DECLARE_DELAYED_SINGLETON(SandboxManagerService);
    DECLEAR_SYSTEM_ABILITY(SandboxManagerService);

public:
    SandboxManagerService(int saId, bool runOnCreate);
    void OnStart() override;
    void OnStop() override;
    void OnStart(const SystemAbilityOnDemandReason& startReason) override;

    int32_t PersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) override;
    int32_t UnPersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) override;
    int32_t PersistPolicyByTokenId(
        uint64_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) override;
    int32_t UnPersistPolicyByTokenId(
        uint64_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) override;
    int32_t SetPolicy(uint64_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag)   override;
    int32_t StartAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) override;
    int32_t StopAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result) override;
    int32_t CheckPersistPolicy(
        uint64_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result) override;
    void onRemovePackage(uint64_t tokenId);

    void DelayUnloadService() override;
    
private:
    bool Initialize();
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    bool StartByEventAction(const SystemAbilityOnDemandReason& startReason);

    std::mutex stateMutex_;
    ServiceRunningState state_;
    std::shared_ptr<EventHandler> unloadHandler_ = nullptr;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // SANDBOX_MANAGER_SERVICE_H