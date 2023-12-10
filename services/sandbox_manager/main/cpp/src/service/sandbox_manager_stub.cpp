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

#include "sandbox_manager_stub.h"

#include <cstdint>
#include <unistd.h>
#include <vector>
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "policy_info.h"
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
            (this->*requestFunc)(data, reply);
        } else {
            // when valid code without any function to handle
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    } else {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option); // when code invalid
    }

    return NO_ERROR;
}

void SandboxManagerStub::persistPermissionInner(MessageParcel &data, MessageParcel &reply)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckAccessPersistPermission(callingTokenId)) {
        reply.WriteUint32(PERMISSION_DENIED);
        return;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        reply.WriteUint32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    
    std::vector<uint32_t> result;
    int32_t ret = this->persistPermission(policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return;
    }

    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager vector parcel fail");
        return;
    }
    return;
}

void SandboxManagerStub::unPersistPermissionInner(MessageParcel &data, MessageParcel &reply)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckAccessPersistPermission(callingTokenId)) {
        reply.WriteUint32(PERMISSION_DENIED);
        return;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        reply.WriteUint32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    
    std::vector<uint32_t> result;
    
    int32_t ret = this->unPersistPermission(policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return;
    }

    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager vector parcel fail");
        return;
    }
    return;
}

void SandboxManagerStub::setPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckSetPolicyPermission(callingTokenId)) {
        reply.WriteUint32(PERMISSION_DENIED);
        return;
    }

    uint64_t tokenid;
    if (!data.ReadUint64(tokenid)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply tokenid parcel fail");
        reply.WriteUint32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        reply.WriteUint32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }

    uint64_t policyFlag;
    if (!data.ReadUint64(policyFlag)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read policyFlag parcel fail");
        reply.WriteUint32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    
    int32_t ret = this->setPolicy(tokenid, policyInfoVectorParcel->policyVector, policyFlag);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    return;
}

void SandboxManagerStub::startAccessingPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckAccessPersistPermission(callingTokenId)) {
        reply.WriteUint32(PERMISSION_DENIED);
        return;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        reply.WriteUint32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    
    std::vector<uint32_t> result;
    int32_t ret = this->startAccessingPolicy(policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return;
    }

    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write sandbox manager reply parcel fail");
        return;
    }
    return;
}

void SandboxManagerStub::stopAccessingPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!CheckAccessPersistPermission(callingTokenId)) {
        reply.WriteUint32(PERMISSION_DENIED);
        return;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        reply.WriteUint32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    
    std::vector<uint32_t> result;
    
    int32_t ret = this->stopAccessingPolicy(policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return;
    }

    if (!reply.WriteUInt32Vector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write sandbox manager reply parcel fail");
        return;
    }
    return;
}

void SandboxManagerStub::checkPersistPermissionInner(MessageParcel &data, MessageParcel &reply)
{
    uint64_t tokenid;
    if (!data.ReadUint64(tokenid)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply tokenid parcel fail");
        reply.WriteUint32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }

    sptr<PolicyInfoVectorParcel> policyInfoVectorParcel = data.ReadParcelable<PolicyInfoVectorParcel>();
    if (policyInfoVectorParcel == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager data parcel fail");
        reply.WriteUint32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }

    std::vector<bool> result;
    int32_t ret = this->checkPersistPermission(tokenid, policyInfoVectorParcel->policyVector, result);
    if (!reply.WriteInt32(ret)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "reply sandbox manager ret parcel fail");
        reply.WriteInt32(SANDBOX_MANAGER_SERVICE_PARCEL_ERR);
        return;
    }
    if (ret != SANDBOX_MANAGER_OK) {
        return;
    }

    if (!reply.WriteBoolVector(result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write sandbox manager reply parcel fail");
        return;
    }
    return;
}

void SandboxManagerStub::SetPolicyOpFuncInMap()
{
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::PERSIST_PERMISSION)] =
        &SandboxManagerStub::persistPermissionInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::UNPERSIST_PERMISSION)] =
        &SandboxManagerStub::unPersistPermissionInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::SET_POLICY)] =
        &SandboxManagerStub::setPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::START_ACCESSING_URI)] =
        &SandboxManagerStub::startAccessingPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::STOP_ACCESSING_URI)] =
        &SandboxManagerStub::stopAccessingPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(SandboxManagerInterfaceCode::CHECK_PERSIST_PERMISSION)] =
        &SandboxManagerStub::checkPersistPermissionInner;
}

SandboxManagerStub::SandboxManagerStub()
{
    SetPolicyOpFuncInMap();
}

SandboxManagerStub::~SandboxManagerStub()
{
    requestFuncMap_.clear();
}

bool SandboxManagerStub::CheckAccessPersistPermission(const uint64_t tokenid)
{
    uint32_t ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(
        tokenid, ACCESS_PERSIST_PERMISSION_NAME);
    if (ret == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Check permission token:%{public}lu pass", tokenid);
        return true;
    }
    SANDBOXMANAGER_LOG_ERROR(LABEL, "Check permission token:%{public}lu fail", tokenid);
    return false;
}

bool SandboxManagerStub::CheckSetPolicyPermission(const uint64_t tokenid)
{
    uint32_t ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenid, SET_POLICY_PERMISSION_NAME);
    if (ret == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        SANDBOXMANAGER_LOG_INFO(LABEL, "Check permission token:%{public}lu pass", tokenid);
        return true;
    }
    SANDBOXMANAGER_LOG_ERROR(LABEL, "Check permission token:%{public}lu fail", tokenid);
    return false;
}

} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
