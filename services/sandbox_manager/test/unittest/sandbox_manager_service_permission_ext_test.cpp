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
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "errors.h"
#include "hap_token_info.h"
#include "nativetoken_kit.h"
#include "permission_status_info_vec_raw_data.h"
#include "policy_info.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_err_code.h"
#define private public
#include "policy_info_manager.h"
#include "sandbox_manager_service.h"
#undef private
#include "sandbox_test_common.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
const std::string UGC_MUSIC_PATH = "/storage/Users/currentUser/Music";
const std::string UGC_IMAGES_PATH = "/storage/Users/currentUser/Images";
const std::string VOLUME_MOUNT_PATH = "/storage/External/ut_service_wrapper";
const uint32_t INVALID_TOKEN_ID = 0;
const uint32_t TEST_CALLBACK_CODE = 0;

Security::AccessToken::PermissionStateFull g_grantState = {
    .permissionName = GRANT_SENSITIVE_PERMISSIONS_NAME,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_revokeState = {
    .permissionName = REVOKE_SENSITIVE_PERMISSIONS_NAME,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_getStatusState = {
    .permissionName = GET_SENSITIVE_PERMISSIONS_NAME,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::PermissionStateFull g_setPolicyState = {
    .permissionName = SET_POLICY_PERMISSION_NAME,
    .isGeneral = true,
    .resDeviceID = {"1"},
    .grantStatus = {0},
    .grantFlags = {0},
};
Security::AccessToken::HapInfoParams g_grantInfoParms = {
    .userID = 1,
    .bundleName = "sandbox_manager_perm_ext_test",
    .instIndex = 0,
    .appIDDesc = "test",
    .isSystemApp = true
};
Security::AccessToken::HapPolicyParams g_grantPolicyPrams = {
    .apl = Security::AccessToken::APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {g_grantState, g_revokeState, g_getStatusState, g_setPolicyState}
};
Security::AccessToken::HapInfoParams g_limitedInfoParms = {
    .userID = 1,
    .bundleName = "sandbox_manager_perm_ext_test_limited",
    .instIndex = 0,
    .appIDDesc = "test",
    .isSystemApp = true
};
Security::AccessToken::HapPolicyParams g_limitedPolicyPrams = {
    .apl = Security::AccessToken::APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {}
};

void AppendRawUint32(std::stringstream &ss, uint32_t value)
{
    ss.write(reinterpret_cast<const char *>(&value), sizeof(value));
}

PolicyVecRawData BuildTruncatedRawData(void)
{
    std::stringstream ss;
    AppendRawUint32(ss, 1); // policy count = 1
    AppendRawUint32(ss, POLICY_PATH_LIMIT); // declared path length without path payload
    PolicyVecRawData rawData;
    rawData.serializedData = ss.str();
    rawData.data = reinterpret_cast<const void *>(rawData.serializedData.data());
    rawData.size = static_cast<uint32_t>(rawData.serializedData.size());
    return rawData;
}
};

class SandboxManagerServicePermissionExtTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<SandboxManagerService> sandboxManagerService_;
    uint64_t selfTokenId_ = 1;
    uint64_t sysGrantToken_;
    uint64_t sysLimitedToken_;
    uint32_t sysGrantTokenId_ = 0;
    uint32_t sysLimitedTokenId_ = 0;
    bool fileManagerPresent_ = false;
};

void SandboxManagerServicePermissionExtTest::SetUpTestCase(void)
{
    if (PolicyInfoManager::GetInstance().macAdapter_.fd_ > 0) {
        close(PolicyInfoManager::GetInstance().macAdapter_.fd_);
        PolicyInfoManager::GetInstance().macAdapter_.fd_ = -1;
        PolicyInfoManager::GetInstance().macAdapter_.isMacSupport_ = false;
    }
    PolicyInfoManager::GetInstance().macAdapter_.Init();
}

void SandboxManagerServicePermissionExtTest::TearDownTestCase(void)
{}

void SandboxManagerServicePermissionExtTest::SetUp(void)
{
    EXPECT_TRUE(MockTokenId("foundation"));
    fileManagerPresent_ = (GetTokenIdFromProcess("file_manager_service") != 0);
    sandboxManagerService_ = DelayedSingleton<SandboxManagerService>::GetInstance();
    ASSERT_NE(nullptr, sandboxManagerService_);

    selfTokenId_ = GetSelfTokenID();
    Security::AccessToken::AccessTokenIDEx grantIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(
        g_grantInfoParms, g_grantPolicyPrams);
    ASSERT_NE(0, grantIdEx.tokenIdExStruct.tokenID);
    sysGrantToken_ = grantIdEx.tokenIDEx;
    sysGrantTokenId_ = grantIdEx.tokenIdExStruct.tokenID;

    Security::AccessToken::AccessTokenIDEx limitedIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(
        g_limitedInfoParms, g_limitedPolicyPrams);
    ASSERT_NE(0, limitedIdEx.tokenIdExStruct.tokenID);
    sysLimitedToken_ = limitedIdEx.tokenIDEx;
    sysLimitedTokenId_ = limitedIdEx.tokenIdExStruct.tokenID;
}

void SandboxManagerServicePermissionExtTest::TearDown(void)
{
    sandboxManagerService_ = nullptr;
    Security::AccessToken::AccessTokenKit::DeleteToken(sysGrantToken_);
    Security::AccessToken::AccessTokenKit::DeleteToken(sysLimitedToken_);
}

/**
 * @tc.name: GrantPermissionByUserTest001
 * @tc.desc: Test GrantPermissionByUser with non-system-app caller, no-permission caller,
 *           zero tokenId and empty policies
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServicePermissionExtTest, GrantPermissionByUserTest001, TestSize.Level0)
{
    std::vector<PolicyInfo> policies = {
        {UGC_MUSIC_PATH, OperateMode::READ_MODE},
    };
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policies);
    PolicyVecRawData emptyRawData;
    emptyRawData.Marshalling({});

    EXPECT_EQ(SANDBOX_MANAGER_NOT_SYS_APP,
        sandboxManagerService_->GrantPermissionByUser(sysLimitedTokenId_, policyRawData));
    EXPECT_EQ(0, SetSelfTokenID(sysLimitedToken_));
    EXPECT_EQ(PERMISSION_DENIED, sandboxManagerService_->GrantPermissionByUser(sysLimitedTokenId_, policyRawData));
    EXPECT_EQ(0, SetSelfTokenID(sysGrantToken_));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->GrantPermissionByUser(INVALID_TOKEN_ID, policyRawData));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->GrantPermissionByUser(sysLimitedTokenId_, emptyRawData));
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: GrantPermissionByUserTest002
 * @tc.desc: Test GrantPermissionByUser with corrupted policy raw data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServicePermissionExtTest, GrantPermissionByUserTest002, TestSize.Level0)
{
    EXPECT_EQ(0, SetSelfTokenID(sysGrantToken_));
    int32_t ret = sandboxManagerService_->GrantPermissionByUser(sysLimitedTokenId_, BuildTruncatedRawData());
    EXPECT_NE(SANDBOX_MANAGER_OK, ret);
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: GrantPermissionByUserTest003
 * @tc.desc: Test GrantPermissionByUser with valid input, then query status by GetStatusByPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServicePermissionExtTest, GrantPermissionByUserTest003, TestSize.Level0)
{
    std::vector<PolicyInfo> policies = {
        {UGC_MUSIC_PATH, OperateMode::READ_MODE},
        {UGC_IMAGES_PATH, OperateMode::READ_MODE | OperateMode::WRITE_MODE},
    };
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policies);

    EXPECT_EQ(0, SetSelfTokenID(sysGrantToken_));
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->GrantPermissionByUser(sysLimitedTokenId_, policyRawData));

    Uint32VecRawData tokenIdListRaw;
    tokenIdListRaw.Marshalling({sysLimitedTokenId_});
    PermissionStatusInfoVecRawData statusRaw;
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->GetStatusByPermission(tokenIdListRaw, statusRaw));
    std::vector<PermissionStatusInfo> status;
    EXPECT_EQ(SANDBOX_MANAGER_OK, statusRaw.Unmarshalling(status));
    ASSERT_EQ(policies.size(), status.size());
    for (const auto &item : status) {
        EXPECT_EQ(static_cast<int32_t>(UGC_PERMISSION_GRANTED), item.grantStatus);
    }
    PolicyInfoManager::GetInstance().RemoveUgcPermissionByTokenId(sysLimitedTokenId_);
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: RevokePermissionByUserTest001
 * @tc.desc: Test RevokePermissionByUser with non-system-app caller, no-permission caller,
 *           zero tokenId and empty policies
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServicePermissionExtTest, RevokePermissionByUserTest001, TestSize.Level0)
{
    std::vector<PolicyInfo> policies = {
        {UGC_MUSIC_PATH, OperateMode::READ_MODE},
    };
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policies);
    PolicyVecRawData emptyRawData;
    emptyRawData.Marshalling({});

    EXPECT_EQ(SANDBOX_MANAGER_NOT_SYS_APP,
        sandboxManagerService_->RevokePermissionByUser(sysLimitedTokenId_, policyRawData));
    EXPECT_EQ(0, SetSelfTokenID(sysLimitedToken_));
    EXPECT_EQ(PERMISSION_DENIED, sandboxManagerService_->RevokePermissionByUser(sysLimitedTokenId_, policyRawData));
    EXPECT_EQ(0, SetSelfTokenID(sysGrantToken_));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->RevokePermissionByUser(INVALID_TOKEN_ID, policyRawData));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->RevokePermissionByUser(sysLimitedTokenId_, emptyRawData));
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: RevokePermissionByUserTest002
 * @tc.desc: Test RevokePermissionByUser with native target token and no granted record, no status change
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServicePermissionExtTest, RevokePermissionByUserTest002, TestSize.Level0)
{
    std::vector<PolicyInfo> policies = {
        {UGC_MUSIC_PATH, OperateMode::READ_MODE},
    };
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policies);

    uint32_t nativeTarget = static_cast<uint32_t>(selfTokenId_);
    EXPECT_EQ(0, SetSelfTokenID(sysGrantToken_));
    // native token is not TOKEN_HAP and has no granted record, revoke succeeds without kill
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->RevokePermissionByUser(nativeTarget, policyRawData));
    PolicyInfoManager::GetInstance().RemoveUgcPermissionByTokenId(nativeTarget);
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: RevokePermissionByUserTest003
 * @tc.desc: Test RevokePermissionByUser with granted hap target, status change triggers kill path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServicePermissionExtTest, RevokePermissionByUserTest003, TestSize.Level0)
{
    std::vector<PolicyInfo> policies = {
        {UGC_MUSIC_PATH, OperateMode::READ_MODE},
    };
    PolicyVecRawData policyRawData;
    policyRawData.Marshalling(policies);

    EXPECT_EQ(0, SetSelfTokenID(sysGrantToken_));
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->GrantPermissionByUser(sysLimitedTokenId_, policyRawData));
    // granted record exists, revoke flips status and enters kill path for hap token without running process
    int32_t ret = sandboxManagerService_->RevokePermissionByUser(sysLimitedTokenId_, policyRawData);
    EXPECT_TRUE(ret == SANDBOX_MANAGER_OK || ret == SANDBOX_MANAGER_KILL_PROCESS_ERR);
    PolicyInfoManager::GetInstance().RemoveUgcPermissionByTokenId(sysLimitedTokenId_);
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: GetStatusByPermissionTest001
 * @tc.desc: Test GetStatusByPermission with non-system-app caller, no-permission caller,
 *           empty list, zero tokenId and unknown token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServicePermissionExtTest, GetStatusByPermissionTest001, TestSize.Level0)
{
    Uint32VecRawData emptyListRaw;
    emptyListRaw.Marshalling({});
    Uint32VecRawData zeroTokenListRaw;
    zeroTokenListRaw.Marshalling({INVALID_TOKEN_ID});
    Uint32VecRawData tokenIdListRaw;
    tokenIdListRaw.Marshalling({sysLimitedTokenId_});
    PermissionStatusInfoVecRawData statusRaw;

    EXPECT_EQ(SANDBOX_MANAGER_NOT_SYS_APP, sandboxManagerService_->GetStatusByPermission(tokenIdListRaw, statusRaw));
    EXPECT_EQ(0, SetSelfTokenID(sysLimitedToken_));
    EXPECT_EQ(PERMISSION_DENIED, sandboxManagerService_->GetStatusByPermission(tokenIdListRaw, statusRaw));
    EXPECT_EQ(0, SetSelfTokenID(sysGrantToken_));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->GetStatusByPermission(emptyListRaw, statusRaw));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->GetStatusByPermission(zeroTokenListRaw, statusRaw));
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->GetStatusByPermission(tokenIdListRaw, statusRaw));
    std::vector<PermissionStatusInfo> status;
    EXPECT_EQ(SANDBOX_MANAGER_OK, statusRaw.Unmarshalling(status));
    EXPECT_EQ(0u, status.size());
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

/**
 * @tc.name: CheckPermissionTest001
 * @tc.desc: Test CheckPermission with granted token and ungranted token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServicePermissionExtTest, CheckPermissionTest001, TestSize.Level0)
{
    EXPECT_TRUE(sandboxManagerService_->CheckPermission(sysGrantTokenId_, SET_POLICY_PERMISSION_NAME));
    EXPECT_FALSE(sandboxManagerService_->CheckPermission(sysLimitedTokenId_, SET_POLICY_PERMISSION_NAME));
}

/**
 * @tc.name: GetUserIdByTokenTest001
 * @tc.desc: Test GetUserIdByToken with allocated hap token and unknown token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServicePermissionExtTest, GetUserIdByTokenTest001, TestSize.Level0)
{
    int32_t userId = 0;
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->GetUserIdByToken(sysGrantTokenId_, userId));
    EXPECT_EQ(g_grantInfoParms.userID, userId);
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->GetUserIdByToken(INVALID_TOKEN_ID, userId));
}

/**
 * @tc.name: CallbackEnterExitTest001
 * @tc.desc: Test CallbackEnter and CallbackExit return ERR_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServicePermissionExtTest, CallbackEnterExitTest001, TestSize.Level0)
{
    EXPECT_EQ(ERR_OK, sandboxManagerService_->CallbackEnter(TEST_CALLBACK_CODE));
    EXPECT_EQ(ERR_OK, sandboxManagerService_->CallbackExit(TEST_CALLBACK_CODE, ERR_OK));
}

/**
 * @tc.name: DeactiveAndActivePolicyByPathTest001
 * @tc.desc: Test Deactive/ActivePolicyByPath with non-file-manager caller and invalid/valid path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxManagerServicePermissionExtTest, DeactiveAndActivePolicyByPathTest001, TestSize.Level0)
{
    EXPECT_EQ(PERMISSION_DENIED, sandboxManagerService_->DeactivePolicyByPath(VOLUME_MOUNT_PATH));
    EXPECT_EQ(PERMISSION_DENIED, sandboxManagerService_->ActivePolicyByPath(VOLUME_MOUNT_PATH));
    if (!fileManagerPresent_) {
        return;
    }
    uint32_t fileManagerToken = Security::AccessToken::AccessTokenKit::GetNativeTokenId("file_manager_service");
    EXPECT_EQ(0, SetSelfTokenID(fileManagerToken));
    std::string overlongPath(POLICY_PATH_LIMIT + 1, '/');
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->DeactivePolicyByPath(""));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->DeactivePolicyByPath(overlongPath));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->ActivePolicyByPath(""));
    EXPECT_EQ(INVALID_PARAMTER, sandboxManagerService_->ActivePolicyByPath(overlongPath));
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->DeactivePolicyByPath(VOLUME_MOUNT_PATH));
    EXPECT_EQ(SANDBOX_MANAGER_OK, sandboxManagerService_->ActivePolicyByPath(VOLUME_MOUNT_PATH));
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}
}
}
}
