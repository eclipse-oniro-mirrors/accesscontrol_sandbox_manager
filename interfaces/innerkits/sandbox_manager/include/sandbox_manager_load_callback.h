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

#ifndef SANDBOX_MANAGER_LOAD_CALLBACK_H
#define SANDBOX_MANAGER_LOAD_CALLBACK_H
#include <cstdint>
#include "i_sandbox_manager.h"
#include "system_ability_load_callback_stub.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class SandboxManagerLoadCallback : public SystemAbilityLoadCallbackStub {
public:
    explicit SandboxManagerLoadCallback();

    void OnLoadSystemAbilitySuccess(int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject);
    void OnLoadSystemAbilityFail(int32_t systemAbilityId);
};
} // SandboxManager
} // AccessControl
} // OHOS
#endif // SANDBOX_MANAGER_LOAD_CALLBACK_H