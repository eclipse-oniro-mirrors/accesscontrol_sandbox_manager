/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "package_uninstall_observer.h"

#include <string>
#include "policy_info_manager.h"
#include "sandbox_manager_log.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "PkgUninstallObserver"
};
}

PkgUninstallObserver::PkgUninstallObserver(const EventFwk::CommonEventSubscribeInfo& subscribeInfo)
    : CommonEventSubscriber(subscribeInfo)
{}

void PkgUninstallObserver::OnReceiveEvent(const EventFwk::CommonEventData& data)
{
    std::string action = data.GetWant().GetAction();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED) {
        uint64_t tokenId = data.GetWant().GetParams().GetIntParam("accessTokenId", 0);
        if (tokenId == 0) {
            SANDBOXMANAGER_LOG_ERROR(LABEL, "Error Tokenid: %{public}lu", tokenId);
        }

        SANDBOXMANAGER_LOG_INFO(LABEL, "action %{public}s bundle:%{public}lu is uninstall", action.c_str(), tokenId);
        PolicyInfoManager::GetInstance().RemoveBundlePolicy(tokenId);
    }
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS