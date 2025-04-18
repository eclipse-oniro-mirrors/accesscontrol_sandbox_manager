/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "sandbox_manager_stub.h"

#include <cinttypes>
#include <cstdint>
#include <string>
#include <unistd.h>
#include <vector>
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "policy_info.h"
#include "policy_info_parcel.h"
#include "policy_info_vector_parcel.h"
#include "sandbox_manager_const.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "sandbox_manager_service.h"
#include "string"
#include "string_ex.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerStub"};
}

static bool CheckPermission(const uint32_t tokenId, const std::string &permission);

int32_t SandboxManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    SANDBOXMANAGER_LOG_DEBUG(LABEL, "code %{public}u token %{public}u", code, callingTokenID);
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != ISandboxManager::GetDescriptor()) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return -1;
    }
    DelayUnloadService();
    auto itFunc = requestFuncMap_.find(code);
    if (itFunc != requestFuncMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            return (this->*requestFunc)(data, reply);
        } else {
            // when valid code without any function to handle
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    } else {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option); // when code invalid
    }

    return NO_ERROR;
}

int32_t SandboxManagerStub::CleanPersistPolicyByPathInner(MessageParcel &data, MessageParcel &reply)
{
    SANDBOXMANAGER_LOG_INFO(LABEL, "Call CleanPersistPolicyByPathInner");
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!IsFileManagerCalling(callingTokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Permission denied(tokenID=%{public}d)", callingTokenId);
        return PERMISSION_DENIED;
    }

    std::vector<std::string> filePathList;
    if (!data.ReadStringVector(&filePathList)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read filePathList failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    
    this->CleanPersistPolicyByPath(filePathList);
    SANDBOXMANAGER_LOG_INFO(LABEL, "End CleanPersistPolicyByPathInner");
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerStub::PersistPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    std::vector<uint32_t> result;
    int32_t ret = this->PersistPolicy(policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager vector parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerStub::UnPersistPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read sandbox manager data parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    std::vector<uint32_t> result;

    int32_t ret = this->UnPersistPolicy(policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager vector parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerStub::PersistPolicyByTokenIdInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }
    uint32_t tokenId;
    if (!data.ReadUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read tokenId parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read sandbox manager data parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    std::vector<uint32_t> result;
    int32_t ret = this->PersistPolicyByTokenId(tokenId, policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager vector parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerStub::UnPersistPolicyByTokenIdInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }
    uint32_t tokenId;
    if (!data.ReadUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply tokenId parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    std::vector<uint32_t> result;

    int32_t ret = this->UnPersistPolicyByTokenId(tokenId, policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager vector parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return SANDBOX_MANAGER_OK;
}

static int32_t ReadSetPolicyParcel(MessageParcel &data, uint32_t &tokenId,
    sptr<PolicyInfoVectorParcel> &policyInfoVectorParcel, uint64_t &policyFlag)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, SET_POLICY_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }

    if (!data.ReadUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read tokenId failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read policyInfoVectorParcel failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.ReadUint64(policyFlag)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read policyFlag failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerStub::SetPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t tokenId;
    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = nullptr;
    uint64_t policyFlag;
    int32_t readRes = ReadSetPolicyParcel(data, tokenId, policyInfoVectorParcel, policyFlag);
    if (readRes != SANDBOX_MANAGER_OK) {
        return readRes;
    }

    std::vector<uint32_t> result;
    int32_t ret = this->SetPolicy(tokenId, policyInfoVectorParcel->policyVector, policyFlag, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write ret failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write result failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerStub::SetPolicyAsyncInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t tokenId;
    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = nullptr;
    uint64_t policyFlag;
    int32_t readRes = ReadSetPolicyParcel(data, tokenId, policyInfoVectorParcel, policyFlag);
    if (readRes != SANDBOX_MANAGER_OK) {
        return readRes;
    }

    return this->SetPolicyAsync(tokenId, policyInfoVectorParcel->policyVector, policyFlag);
}

static int32_t ReadUnSetPolicyParcel(MessageParcel &data, uint32_t &tokenId,
    sptr<PolicyInfoParcel> &policyInfoParcel)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, SET_POLICY_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }

    if (!data.ReadUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read tokenId failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    policyInfoParcel = data.ReadParcelable<PolicyInfoParcel>();
    if (policyInfoParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read policyInfoParcel failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerStub::UnSetPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t tokenId;
    sptr<PolicyInfoParcel> policyInfoParcel = nullptr;
    int32_t readRes = ReadUnSetPolicyParcel(data, tokenId, policyInfoParcel);
    if (readRes != SANDBOX_MANAGER_OK) {
        return readRes;
    }

    int32_t ret = this->UnSetPolicy(tokenId, policyInfoParcel->policyInfo);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write ret failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerStub::UnSetPolicyAsyncInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t tokenId;
    sptr<PolicyInfoParcel> policyInfoParcel = nullptr;
    int32_t readRes = ReadUnSetPolicyParcel(data, tokenId, policyInfoParcel);
    if (readRes != SANDBOX_MANAGER_OK) {
        return readRes;
    }

    return this->UnSetPolicyAsync(tokenId, policyInfoParcel->policyInfo);
}

int32_t SandboxManagerStub::CheckPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t tokenId;
    if (!data.ReadUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read tokenId failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read policyInfoVectorParcel failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    std::vector<bool> result;
    int32_t ret = this->CheckPolicy(tokenId, policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write ret failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }
    if (!reply.WriteBoolVector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write result failed.");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerStub::StartAccessingPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    std::vector<uint32_t> result;
    int32_t ret = this->StartAccessingPolicy(policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write sandbox manager reply parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerStub::StopAccessingPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, ACCESS_PERSIST_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    std::vector<uint32_t> result;

    int32_t ret = this->StopAccessingPolicy(policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write sandbox manager reply parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerStub::CheckPersistPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t tokenId;
    if (!data.ReadUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply tokenId parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    std::vector<bool> result;
    int32_t ret = this->CheckPersistPolicy(tokenId, policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return ret;
    }

    if (!reply.WriteBoolVector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write sandbox manager reply parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerStub::StartAccessingByTokenIdInner(MessageParcel &data, MessageParcel &reply)
{
    if (IPCSkeleton::GetCallingUid() != FOUNDATION_UID) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Not foundation userid, permision denied.");
        return PERMISSION_DENIED;
    }
    uint32_t tokenId;
    if (!data.ReadUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read tokenId parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    this->StartAccessingByTokenId(tokenId);
    return SANDBOX_MANAGER_OK;
}

int32_t SandboxManagerStub::UnSetAllPolicyByTokenInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckPermission(callingTokenId, SET_POLICY_PERMISSION_NAME)) {
        return PERMISSION_DENIED;
    }

    uint32_t tokenId;
    if (!data.ReadUint32(tokenId)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Read tokenId parcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    this->UnSetAllPolicyByToken(tokenId);
    return SANDBOX_MANAGER_OK;
}

void SandboxManagerStub::SetPolicyOpFuncInMap()
{
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::CLEAN_PERSIST_POLICY_BY_PATH)] =
        &SandboxManagerStub::CleanPersistPolicyByPathInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::PERSIST_PERMISSION)] =
        &SandboxManagerStub::PersistPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::UNPERSIST_PERMISSION)] =
        &SandboxManagerStub::UnPersistPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::PERSIST_PERMISSION_BY_TOKENID)] =
        &SandboxManagerStub::PersistPolicyByTokenIdInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::UNPERSIST_PERMISSION_BY_TOKENID)] =
        &SandboxManagerStub::UnPersistPolicyByTokenIdInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::SET_POLICY)] =
        &SandboxManagerStub::SetPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::UNSET_POLICY)] =
        &SandboxManagerStub::UnSetPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::SET_POLICY_ASYNC)] =
        &SandboxManagerStub::SetPolicyAsyncInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::UNSET_POLICY_ASYNC)] =
        &SandboxManagerStub::UnSetPolicyAsyncInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::CHECK_POLICY)] =
        &SandboxManagerStub::CheckPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::START_ACCESSING_URI)] =
        &SandboxManagerStub::StartAccessingPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::STOP_ACCESSING_URI)] =
        &SandboxManagerStub::StopAccessingPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::CHECK_PERSIST_PERMISSION)] =
        &SandboxManagerStub::CheckPersistPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::START_ACCESSING_BY_TOKEN)] =
        &SandboxManagerStub::StartAccessingByTokenIdInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::UNSET_ALL_POLICY_BY_TOKEN)] =
        &SandboxManagerStub::UnSetAllPolicyByTokenInner;
}

SandboxManagerStub::SandboxManagerStub()
{
    SetPolicyOpFuncInMap();
}

SandboxManagerStub::~SandboxManagerStub()
{
    requestFuncMap_.clear();
}

bool CheckPermission(const uint32_t tokenId, const std::string &permission)
{
    int32_t ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permission);
    if (ret == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Check permission token:%{public}d pass", tokenId);
        return true;
    }
    SANDBOXMANAGER_LOG_ERROR(LABEL, "Check permission token:%{public}d fail", tokenId);
    return false;
}
bool SandboxManagerStub::IsFileManagerCalling(uint32_t tokenCaller)
{
    if (tokenFileManagerId_ == 0) {
        tokenFileManagerId_ = Security::AccessToken::AccessTokenKit::GetNativeTokenId(
            "file_manager_service");
    }
    return tokenCaller == tokenFileManagerId_;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS