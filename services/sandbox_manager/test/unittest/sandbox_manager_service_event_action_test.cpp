/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <map>
#include <string>
#include <unistd.h>
#include <vector>
#include "common_event_support.h"
#include "policy_info.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_err_code.h"
#define private public
#include "policy_info_manager.h"
#include "sandbox_manager_service.h"
#undef private
#include "sandbox_test_common.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
const std::string PRESERVE_CONFIG_KEY = "ohos.fileshare.supportPreservePersistentPermission";
const std::string OVERFLOW_NUMBER = "99999999999999999999";
const std::string TEST_BUNDLE_NAME = "test.bundle.event.action";
const std::string TEST_USER_ID = "100";
const std::string TEST_ACCESS_TOKEN_ID = "12345";
const std::string TEST_APP_IDENTIFIER = "test.bundle.event.action.identifier";

SystemAbilityOnDemandReason BuildReason(const std::string &name, const std::map<std::string, std::string> &want)
{
    SystemAbilityOnDemandReason reason;
    reason.SetName(name);
    OnDemandReasonExtraData extraData(0, "test", want);
    reason.SetExtraData(extraData);
    return reason;
}
};

class SandboxManagerServiceEventActionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<SandboxManagerService> sandboxManagerService_;
};

void SandboxManagerServiceEventActionTest::SetUpTestCase(void)
{
    if (PolicyInfoManager::GetInstance().macAdapter_.fd_ > 0) {
        close(PolicyInfoManager::GetInstance().macAdapter_.fd_);
        PolicyInfoManager::GetInstance().macAdapter_.fd_ = -1;
        PolicyInfoManager::GetInstance().macAdapter_.isMacSupport_ = false;
    }
    PolicyInfoManager::GetInstance().macAdapter_.Init();
}

void SandboxManagerServiceEventActionTest::TearDownTestCase(void)
{}

void SandboxManagerServiceEventActionTest::SetUp(void)
{
    EXPECT_TRUE(MockTokenId("foundation"));
    sandboxManagerService_ = DelayedSingleton<SandboxManagerService>::GetInstance();
    ASSERT_NE(nullptr, sandboxManagerService_);
}

void SandboxManagerServiceEventActionTest::TearDown(void)
{
    sandboxManagerService_ = nullptr;
}

/**
 * @tc.name: PackageRemoveEventActionTest001
 * @tc.desc: Test PackageRemoveEventAction with missing preserve config, zero userId,
 *           missing appIndex and missing bundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceEventActionTest, PackageRemoveEventActionTest001, TestSize.Level0)
{
    ASSERT_TRUE(sandboxManagerService_->Initialize());

    std::map<std::string, std::string> missingPreserve = {
        {"accessTokenId", TEST_ACCESS_TOKEN_ID},
        {"bundleName", TEST_BUNDLE_NAME},
        {"userId", TEST_USER_ID},
        {"appIndex", "0"}
    };
    EXPECT_FALSE(sandboxManagerService_->PackageRemoveEventAction(
        BuildReason(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED, missingPreserve)));

    std::map<std::string, std::string> zeroUserId = {
        {"accessTokenId", TEST_ACCESS_TOKEN_ID},
        {"bundleName", TEST_BUNDLE_NAME},
        {"userId", "0"},
        {"appIndex", "0"}
    };
    EXPECT_FALSE(sandboxManagerService_->PackageRemoveEventAction(
        BuildReason(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED, zeroUserId)));

    std::map<std::string, std::string> missingAppIndex = {
        {"accessTokenId", TEST_ACCESS_TOKEN_ID},
        {"bundleName", TEST_BUNDLE_NAME},
        {"userId", TEST_USER_ID}
    };
    EXPECT_FALSE(sandboxManagerService_->PackageRemoveEventAction(
        BuildReason(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED, missingAppIndex)));

    std::map<std::string, std::string> missingBundleName = {
        {"accessTokenId", TEST_ACCESS_TOKEN_ID},
        {"userId", TEST_USER_ID},
        {"appIndex", "0"}
    };
    EXPECT_FALSE(sandboxManagerService_->PackageRemoveEventAction(
        BuildReason(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED, missingBundleName)));
}

/**
 * @tc.name: PackageRemoveEventActionTest002
 * @tc.desc: Test PackageRemoveEventAction with zero accessTokenId and overflow accessTokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceEventActionTest, PackageRemoveEventActionTest002, TestSize.Level0)
{
    ASSERT_TRUE(sandboxManagerService_->Initialize());

    std::map<std::string, std::string> zeroTokenId = {
        {"accessTokenId", "0"},
        {"bundleName", TEST_BUNDLE_NAME},
        {"userId", TEST_USER_ID},
        {"appIndex", "0"}
    };
    EXPECT_FALSE(sandboxManagerService_->PackageRemoveEventAction(
        BuildReason(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED, zeroTokenId)));

    std::map<std::string, std::string> overflowTokenId = {
        {"accessTokenId", OVERFLOW_NUMBER},
        {"bundleName", TEST_BUNDLE_NAME},
        {"userId", TEST_USER_ID},
        {"appIndex", "0"}
    };
    EXPECT_FALSE(sandboxManagerService_->PackageRemoveEventAction(
        BuildReason(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED, overflowTokenId)));
}

/**
 * @tc.name: PackageRemoveEventActionTest003
 * @tc.desc: Test PackageRemoveEventAction with sub-mode main app index, preserve and remove flows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceEventActionTest, PackageRemoveEventActionTest003, TestSize.Level0)
{
    ASSERT_TRUE(sandboxManagerService_->Initialize());

    std::map<std::string, std::string> subModePreserve = {
        {"accessTokenId", TEST_ACCESS_TOKEN_ID},
        {"bundleName", TEST_BUNDLE_NAME},
        {"userId", TEST_USER_ID},
        {"appIndex", std::to_string(SUB_MODE_MAIN_APP_INDEX)},
        {PRESERVE_CONFIG_KEY, "true"},
        {"appIdentifier", TEST_APP_IDENTIFIER}
    };
    EXPECT_TRUE(sandboxManagerService_->PackageRemoveEventAction(
        BuildReason(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED, subModePreserve)));

    std::map<std::string, std::string> subModeRemove = {
        {"accessTokenId", TEST_ACCESS_TOKEN_ID},
        {"bundleName", TEST_BUNDLE_NAME},
        {"userId", TEST_USER_ID},
        {"appIndex", std::to_string(SUB_MODE_MAIN_APP_INDEX)},
        {PRESERVE_CONFIG_KEY, "false"}
    };
    EXPECT_TRUE(sandboxManagerService_->PackageRemoveEventAction(
        BuildReason(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED, subModeRemove)));
}

/**
 * @tc.name: PackageAddEventActionTest001
 * @tc.desc: Test PackageAddEventAction with missing accessTokenId, missing bundleName,
 *           and overflow appIndex
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceEventActionTest, PackageAddEventActionTest001, TestSize.Level0)
{
    ASSERT_TRUE(sandboxManagerService_->Initialize());

    std::map<std::string, std::string> missingBundleName = {
        {"accessTokenId", TEST_ACCESS_TOKEN_ID},
        {"userId", TEST_USER_ID},
        {"appIndex", "0"},
        {"appIdentifier", TEST_APP_IDENTIFIER}
    };
    EXPECT_FALSE(sandboxManagerService_->PackageAddEventAction(
        BuildReason(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED, missingBundleName)));

    std::map<std::string, std::string> overflowAppIndex = {
        {"accessTokenId", TEST_ACCESS_TOKEN_ID},
        {"bundleName", TEST_BUNDLE_NAME},
        {"userId", TEST_USER_ID},
        {"appIndex", OVERFLOW_NUMBER},
        {"appIdentifier", TEST_APP_IDENTIFIER}
    };
    EXPECT_FALSE(sandboxManagerService_->PackageAddEventAction(
        BuildReason(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED, overflowAppIndex)));
}

/**
 * @tc.name: PackageChangedEventActionTest001
 * @tc.desc: Test PackageChangedEventAction with missing isModuleUpdate and false isModuleUpdate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServiceEventActionTest, PackageChangedEventActionTest001, TestSize.Level0)
{
    ASSERT_TRUE(sandboxManagerService_->Initialize());

    std::map<std::string, std::string> missingModuleUpdate = {
        {"accessTokenId", TEST_ACCESS_TOKEN_ID},
        {"bundleName", TEST_BUNDLE_NAME},
        {"userId", TEST_USER_ID},
        {"appIndex", "0"}
    };
    EXPECT_FALSE(sandboxManagerService_->PackageChangedEventAction(
        BuildReason(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED, missingModuleUpdate)));

    std::map<std::string, std::string> notModuleUpdate = {
        {"accessTokenId", TEST_ACCESS_TOKEN_ID},
        {"bundleName", TEST_BUNDLE_NAME},
        {"userId", TEST_USER_ID},
        {"appIndex", "0"},
        {"isModuleUpdate", "false"}
    };
    EXPECT_FALSE(sandboxManagerService_->PackageChangedEventAction(
        BuildReason(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED, notModuleUpdate)));
}
}
}
}
