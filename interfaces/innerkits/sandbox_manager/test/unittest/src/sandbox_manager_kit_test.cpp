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

#include "sandbox_manager_kit_test.h"

#include <cstdint>
#include <vector>
#include "policy_info.h"
#include "sandbox_manager_client.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_kit.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

void SandboxManagerKitTest::SetUpTestCase()
{}

void SandboxManagerKitTest::TearDownTestCase()
{}

void SandboxManagerKitTest::SetUp()
{}

void SandboxManagerKitTest::TearDown()
{}

HWTEST_F(SandboxManagerKitTest, SdkTest001, TestSize.Level1)
{
    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.push_back(info);
    std::vector<uint32_t> result;
    ASSERT_EQ(PERMISSION_DENIED, SandboxManagerKit::persistPermission(policy, result));
    ASSERT_NE(policy.size(), result.size());
}

HWTEST_F(SandboxManagerKitTest, SdkTest002, TestSize.Level1)
{
    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.push_back(info);
    std::vector<uint32_t> result;
    ASSERT_EQ(PERMISSION_DENIED, SandboxManagerKit::unPersistPermission(policy, result));
    ASSERT_NE(policy.size(), result.size());
}

HWTEST_F(SandboxManagerKitTest, SdkTest003, TestSize.Level1)
{
    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.push_back(info);
    std::vector<uint32_t> result;

    uint64_t token = 0;
    uint64_t policyFlag = 0b01;
    ASSERT_EQ(PERMISSION_DENIED, SandboxManagerKit::setPolicy(token, policy, policyFlag));
}

HWTEST_F(SandboxManagerKitTest, SdkTest004, TestSize.Level1)
{
    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.push_back(info);
    std::vector<uint32_t> result;

    ASSERT_EQ(PERMISSION_DENIED, SandboxManagerKit::startAccessingURI(policy, result));
    ASSERT_NE(policy.size(), result.size());
}

HWTEST_F(SandboxManagerKitTest, SdkTest005, TestSize.Level1)
{
    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.push_back(info);
    std::vector<uint32_t> result;

    ASSERT_EQ(PERMISSION_DENIED, SandboxManagerKit::stopAccessingURI(policy, result));
    ASSERT_NE(policy.size(), result.size());
}

HWTEST_F(SandboxManagerKitTest, SdkTest006, TestSize.Level1)
{
    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.push_back(info);
    std::vector<bool> result;
    uint64_t tokenid = 0;

    ASSERT_EQ(SANDBOX_MANAGER_OK, SandboxManagerKit::checkPersistPermission(tokenid, policy, result));
    ASSERT_EQ(policy.size(), result.size());
}
} //SandboxManager
} //AccessControl
} // OHOS