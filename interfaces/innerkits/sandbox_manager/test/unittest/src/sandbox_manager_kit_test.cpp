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
#include "sandbox_manager_kit.h"
#include "sandbox_manager_log.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerKitTest"
};

void SandboxManagerKitTest::SetUpTestCase()
{
}

void SandboxManagerKitTest::TearDownTestCase()
{
}

void SandboxManagerKitTest::SetUp()
{
}

void SandboxManagerKitTest::TearDown()
{
}

HWTEST_F(SandboxManagerKitTest, SdkTest, TestSize.Level1)
{
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "call");
    PolicyInfo info;
    std::vector<PolicyInfo> policy;
    policy.push_back(info);
    std::vector<uint32_t> result;
    ASSERT_EQ(0, SandboxManagerKit::persistPermission(policy, result));
    ASSERT_EQ(0, SandboxManagerKit::unPersistPermission(policy, result));
    uint64_t token = 0;
    ASSERT_EQ(0, SandboxManagerKit::setPolicy(token, policy, result));
    ASSERT_EQ(0, SandboxManagerKit::startAccessingURI(policy, result));
    ASSERT_EQ(0, SandboxManagerKit::stopAccessingURI(policy, result));
    std::vector<bool> tmp;
    ASSERT_EQ(0, SandboxManagerKit::checkPersistPermission(token, policy, tmp));
}

} //SandboxManager
} //AccessControl
} // OHOS