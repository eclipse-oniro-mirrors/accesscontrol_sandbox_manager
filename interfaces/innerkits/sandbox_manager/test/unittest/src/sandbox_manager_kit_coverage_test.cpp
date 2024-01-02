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

#include "sandbox_manager_kit_coverage_test.h"

#include <cstdint>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "permission_def.h"
#include "permission_state_full.h"
#include "policy_info.h"
#include "sandbox_manager_client.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_kit.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static const uint32_t INVALID_POLICY_SIZE = 501;
static const uint32_t VALID_POLICY_SIZE = 10;
const std::string SET_POLICY_PERMISSION = "ohos.permission.SET_SANDBOX_POLICY";
const std::string ACCESS_PERSIST_PERMISSION = "ohos.permission.FILE_ACCESS_PERSIST";
};
void SandboxManagerKitCoverageTest::SetUpTestCase()
{
}

void SandboxManagerKitCoverageTest::TearDownTestCase()
{}

void SandboxManagerKitCoverageTest::SetUp()
{
}

void SandboxManagerKitCoverageTest::TearDown()
{
}

/**
 * @tc.name: PersistPolicy001
 * @tc.desc: PersistPolicy with invalid input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitCoverageTest, PersistPolicy001, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    for (uint32_t i = 0; i < INVALID_POLICY_SIZE; i++) {
        PolicyInfo info;
        policy.emplace_back(info);
    }
    std::vector<uint32_t> result;

    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(policy, result));

    std::vector<PolicyInfo> policyEmpty;
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::PersistPolicy(policyEmpty, result));
    EXPECT_EQ(0, result.size());
}

/**
 * @tc.name: PersistPolicy002
 * @tc.desc: PersistPolicy without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitCoverageTest, PersistPolicy002, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    for (uint32_t i = 0; i < VALID_POLICY_SIZE; i++) {
        PolicyInfo info;
        policy.emplace_back(info);
    }
    std::vector<uint32_t> result;

    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::PersistPolicy(policy, result));
    EXPECT_EQ(0, result.size());
}

/**
 * @tc.name: UnPersistPolicy001
 * @tc.desc: PersistPolicy with invalid input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitCoverageTest, UnPersistPolicy001, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    for (uint32_t i = 0; i < INVALID_POLICY_SIZE; i++) {
        PolicyInfo info;
        policy.emplace_back(info);
    }
    std::vector<uint32_t> result;

    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(policy, result));

    std::vector<PolicyInfo> policyEmpty;
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::UnPersistPolicy(policyEmpty, result));
    EXPECT_EQ(0, result.size());
}

/**
 * @tc.name: UnPersistPolicy002
 * @tc.desc: PersistPolicy without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitCoverageTest, UnPersistPolicy002, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    for (uint32_t i = 0; i < VALID_POLICY_SIZE; i++) {
        PolicyInfo info;
        policy.emplace_back(info);
    }
    std::vector<uint32_t> result;

    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::UnPersistPolicy(policy, result));
    EXPECT_EQ(0, result.size());
}

/**
 * @tc.name: SetPolicy001
 * @tc.desc: SetPolicy without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitCoverageTest, SetPolicy001, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    for (uint32_t i = 0; i < VALID_POLICY_SIZE; i++) {
        PolicyInfo info;
        policy.emplace_back(info);
    }
    std::vector<uint32_t> result;

    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::SetPolicy(GetSelfTokenID(), policy, 0));
    EXPECT_EQ(0, result.size());
}

/**
 * @tc.name: StartAccessingPolicy001
 * @tc.desc: StartAccessingPolicy with invalid input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitCoverageTest, StartAccessingPolicy001, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    for (uint32_t i = 0; i < INVALID_POLICY_SIZE; i++) {
        PolicyInfo info;
        policy.emplace_back(info);
    }
    std::vector<uint32_t> result;

    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::StartAccessingPolicy(policy, result));

    std::vector<PolicyInfo> policyEmpty;
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::StartAccessingPolicy(policyEmpty, result));
    EXPECT_EQ(0, result.size());
}

/**
 * @tc.name: StartAccessingPolicy002
 * @tc.desc: StartAccessingPolicy without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitCoverageTest, StartAccessingPolicy002, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    for (uint32_t i = 0; i < VALID_POLICY_SIZE; i++) {
        PolicyInfo info;
        policy.emplace_back(info);
    }
    std::vector<uint32_t> result;

    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::StartAccessingPolicy(policy, result));
    EXPECT_EQ(0, result.size());
}

/**
 * @tc.name: StopAccessingPolicy001
 * @tc.desc: StopAccessingPolicy with invalid input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitCoverageTest, StopAccessingPolicy001, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    for (uint32_t i = 0; i < INVALID_POLICY_SIZE; i++) {
        PolicyInfo info;
        policy.emplace_back(info);
    }
    std::vector<uint32_t> result;
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::StopAccessingPolicy(policy, result));

    std::vector<PolicyInfo> policyEmpty;
    EXPECT_EQ(INVALID_PARAMTER, SandboxManagerKit::StopAccessingPolicy(policyEmpty, result));
    EXPECT_EQ(0, result.size());
}

/**
 * @tc.name: StopAccessingPolicy002
 * @tc.desc: StopAccessingPolicy without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerKitCoverageTest, StopAccessingPolicy002, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    for (uint32_t i = 0; i < VALID_POLICY_SIZE; i++) {
        PolicyInfo info;
        policy.emplace_back(info);
    }
    std::vector<uint32_t> result;

    EXPECT_EQ(PERMISSION_DENIED, SandboxManagerKit::StopAccessingPolicy(policy, result));
    EXPECT_EQ(0, result.size());
}
} //SandboxManager
} //AccessControl
} // OHOS