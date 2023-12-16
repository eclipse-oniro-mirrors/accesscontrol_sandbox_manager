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

#include <cstdint>
#include <gtest/gtest.h>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "policy_info.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_db.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_service.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

class SandboxManagerServiceTest : public testing::Test  {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void GetTokenid();
    std::shared_ptr<SandboxManagerService> sandboxManagerService_;
    uint64_t selfTokenId_;
    uint64_t sysGrantToken_;
};

PolicyInfo modeErr1, modeErr2, pathErr1, pathErr2, sysGrant, normal1, normal2, normal3;

void SandboxManagerServiceTest::SetUpTestCase(void)
{}

void SandboxManagerServiceTest::TearDownTestCase(void)
{}

void SandboxManagerServiceTest::SetUp(void)
{
    sandboxManagerService_ = DelayedSingleton<SandboxManagerService>::GetInstance();
    EXPECT_NE(nullptr, sandboxManagerService_);
}

void SandboxManagerServiceTest::TearDown(void)
{
    sandboxManagerService_ = nullptr;
}

/**
 * @tc.name: SandboxManagerServiceTest001
 * @tc.desc: Test PersistPolicy - invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest001, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> result0;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->PersistPolicy(policy, result0));
    uint64_t sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result0.size());

    policy.resize(POLICY_VECTOR_SIZE_LIMIT + 1);
    std::vector<uint32_t> result1;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->PersistPolicy(policy, result1));
    sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result1.size());
}

/**
 * @tc.name: SandboxManagerServiceTest002
 * @tc.desc: Test SetPolicy - invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest002, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> result0;
    uint64_t policyFlag = 0;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->SetPolicy(selfTokenId_, policy, policyFlag));
    uint64_t sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result0.size());

    policy.resize(POLICY_VECTOR_SIZE_LIMIT + 1);
    std::vector<uint32_t> result;
    
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->SetPolicy(selfTokenId_, policy, policyFlag));
    sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result.size());

    policy.resize(1);
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->SetPolicy(selfTokenId_, policy, policyFlag));
    policyFlag = 1;
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->SetPolicy(selfTokenId_, policy, policyFlag));
}

/**
 * @tc.name: SandboxManagerServiceTest003
 * @tc.desc: Test StartAccessingPolicy - invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest003, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> result0;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StartAccessingPolicy(policy, result0));
    uint64_t sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result0.size());

    policy.resize(POLICY_VECTOR_SIZE_LIMIT + 1);
    std::vector<uint32_t> result1;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StartAccessingPolicy(policy, result1));
    sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result1.size());
}


/**
 * @tc.name: SandboxManagerServiceTest004
 * @tc.desc: Test StopAccessingPolicy - invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest004, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> result0;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StopAccessingPolicy(policy, result0));
    uint64_t sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result0.size());

    policy.resize(POLICY_VECTOR_SIZE_LIMIT + 1);
    std::vector<uint32_t> result1;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->StopAccessingPolicy(policy, result1));
    sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result1.size());
}

/**
 * @tc.name: SandboxManagerServiceTest005
 * @tc.desc: Test CheckPersistPolicy - invalid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest005, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<bool> result0;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->CheckPersistPolicy(selfTokenId_, policy, result0));
    uint64_t sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result0.size());

    policy.resize(POLICY_VECTOR_SIZE_LIMIT + 1);
    std::vector<bool> result1;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->CheckPersistPolicy(selfTokenId_, policy, result1));
    sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result1.size());
}


/**
 * @tc.name: SandboxManagerServiceTest006
 * @tc.desc: Test UnPersistPolicy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceTest, SandboxManagerServiceTest006, TestSize.Level1)
{
    std::vector<PolicyInfo> policy;
    std::vector<uint32_t> result0;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnPersistPolicy(policy, result0));
    uint64_t sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result0.size());

    policy.resize(POLICY_VECTOR_SIZE_LIMIT + 1);
    std::vector<uint32_t> result1;
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->UnPersistPolicy(policy, result1));
    sizeLimit = 0;
    EXPECT_EQ(sizeLimit, result1.size());
}
} // SandboxManager
} // AccessControl
} // OHOS