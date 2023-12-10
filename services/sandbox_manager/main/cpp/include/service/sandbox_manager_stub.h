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

#ifndef SANDBOX_MANAGER_STUB_H
#define SANDBOX_MANAGER_STUB_H

#include <cstdint>
#include <map>
#include "iremote_stub.h"
#include "i_sandbox_manager.h"
#include "message_parcel.h"
#include "nocopyable.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
class SandboxManagerStub : public IRemoteStub<ISandboxManager> {
public:
    SandboxManagerStub();
    virtual ~SandboxManagerStub();

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &options) override;

    virtual void DelayUnloadService() = 0;

private:
    void persistPermissionInner(MessageParcel &data, MessageParcel &reply);
    void unPersistPermissionInner(MessageParcel &data, MessageParcel &reply);
    void setPolicyInner(MessageParcel &data, MessageParcel &reply);
    void startAccessingPolicyInner(MessageParcel &data, MessageParcel &reply);
    void stopAccessingPolicyInner(MessageParcel &data, MessageParcel &reply);
    void checkPersistPermissionInner(MessageParcel &data, MessageParcel &reply);
    void SetPolicyOpFuncInMap();

    bool CheckAccessPersistPermission(const uint64_t tokenid);
    bool CheckSetPolicyPermission(const uint64_t tokenid);

    using RequestFuncType = void (SandboxManagerStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, RequestFuncType> requestFuncMap_;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // SANDBOX_MANAGER_STUB_H
