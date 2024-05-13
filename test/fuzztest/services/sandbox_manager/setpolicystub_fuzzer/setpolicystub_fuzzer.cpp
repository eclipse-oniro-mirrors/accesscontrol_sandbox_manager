/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "setpolicystub_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include "alloc_token.h"
#include "policy_info_vector_parcel.h"
#include "i_sandbox_manager.h"
#include "sandboxmanager_service_ipc_interface_code.h"
#include "sandbox_manager_service.h"

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
    bool SetPolicyStub(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        std::vector<PolicyInfo> policyVec;
        uint64_t tokenId = static_cast<uint64_t>(size);
        uint64_t policyFlag = static_cast<uint64_t>(size);

        PolicyInfo policy = {
            .path = std::string(reinterpret_cast<const char*>(data), size),
            .mode = static_cast<uint64_t>(size),
        };
        policyVec.emplace_back(policy);

        MessageParcel datas;
        if (!datas.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
            return false;
        }

        if (!datas.WriteUint64(tokenId)) {
            return false;
        }

        PolicyInfoVectorParcel policyInfoParcel;
        policyInfoParcel.policyVector = policyVec;
        if (!datas.WriteParcelable(&policyInfoParcel)) {
            return false;
        }

        if (!datas.WriteUint64(policyFlag)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(SandboxManagerInterfaceCode::SET_POLICY);
        MessageParcel reply;
        MessageOption option;

        DelayedSingleton<SandboxManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        return true;
    }

    bool SetPolicyStubFuzzTest(const uint8_t *data, size_t size)
    {
        return AllocTokenWithFuzz(data, size, SetPolicyStub);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetPolicyStubFuzzTest(data, size);
    return 0;
}