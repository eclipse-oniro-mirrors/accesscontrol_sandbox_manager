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
    void PersistPolicyInner(MessageParcel &data, MessageParcel &reply);
    void UnPersistPolicyInner(MessageParcel &data, MessageParcel &reply);
    void PersistPolicyByTokenIdInner(MessageParcel &data, MessageParcel &reply);
    void UnPersistPolicyByTokenIdInner(MessageParcel &data, MessageParcel &reply);
    void SetPolicyInner(MessageParcel &data, MessageParcel &reply);
    void StartAccessingPolicyInner(MessageParcel &data, MessageParcel &reply);
    void StopAccessingPolicyInner(MessageParcel &data, MessageParcel &reply);
    void CheckPersistPolicyInner(MessageParcel &data, MessageParcel &reply);
    void SetPolicyOpFuncInMap();

    bool CheckPermission(const uint64_t tokenId, const std::string &permission);

    using RequestFuncType = void (SandboxManagerStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, RequestFuncType> requestFuncMap_;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // SANDBOX_MANAGER_STUB_H