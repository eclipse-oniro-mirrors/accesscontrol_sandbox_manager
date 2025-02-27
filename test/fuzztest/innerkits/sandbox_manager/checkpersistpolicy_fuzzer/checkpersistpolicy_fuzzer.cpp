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

#include "checkpersistpolicy_fuzzer.h"

#include <vector>
#include <cstdint>
#include <string>
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_kit.h"

using namespace OHOS::AccessControl::SandboxManager;

namespace OHOS {
    bool CheckPersistPolicyFuzzTest(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        std::vector<PolicyInfo> policyVec;
        std::vector<bool> result;
        uint64_t tokenId = static_cast<uint64_t>(size);

        PolicyInfo policy = {
            .path = std::string(reinterpret_cast<const char*>(data), size),
            .mode = static_cast<uint64_t>(size),
        };
        policyVec.emplace_back(policy);
        
        int32_t ret = SandboxManagerKit::CheckPersistPolicy(tokenId, policyVec, result);
        return ret == SandboxManagerErrCode::SANDBOX_MANAGER_OK;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CheckPersistPolicyFuzzTest(data, size);
    return 0;
}