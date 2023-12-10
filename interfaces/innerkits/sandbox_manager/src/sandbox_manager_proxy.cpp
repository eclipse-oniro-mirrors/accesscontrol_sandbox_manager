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

#include "sandbox_manager_proxy.h"

#include <string>
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "message_parcel.h"
#include "parcel.h"
#include "policy_info_vector_parcel.h"
#include "sandboxmanager_service_ipc_interface_code.h"
#include "sandbox_manager_err_code.h"
#include "sandbox_manager_log.h"
#include "string_ex.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    ACCESSCONTROL_DOMAIN_SANDBOXMANAGER, "SandboxManagerProxy"};
}

SandboxManagerProxy::SandboxManagerProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ISandboxManager>(impl)
{}

SandboxManagerProxy::~SandboxManagerProxy()
{}

bool SandboxManagerProxy::SendRequest(SandboxManagerInterfaceCode code,
    MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "remote service null.");
        return false;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(code), data, reply, option);
    if (requestResult != NO_ERROR) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "request fail, result: %{public}d", requestResult);
        return false;
    }
    return true;
}

int32_t SandboxManagerProxy::persistPermission(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    PolicyInfoVectorParcel policyInfoVectorParcel;
    policyInfoVectorParcel.policyVector = policy;
    if (!data.WriteParcelable(&policyInfoVectorParcel)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policyInfoVectorParcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    
    MessageParcel reply;
    if (!SendRequest(SandboxManagerInterfaceCode::PERSIST_PERMISSION, data, reply)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "remote fail");
        return SANDBOX_MANAGER_SERVICE_REMOTE_ERR;
    }

    int32_t remoteRet;
    if (!reply.ReadInt32(remoteRet)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read ret fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (remoteRet == SANDBOX_MANAGER_OK && !reply.ReadUInt32Vector(&result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read result fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return remoteRet;
}

int32_t SandboxManagerProxy::unPersistPermission(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    PolicyInfoVectorParcel policyInfoVectorParcel;
    policyInfoVectorParcel.policyVector = policy;
    if (!data.WriteParcelable(&policyInfoVectorParcel)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policyInfoVectorParcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    
    MessageParcel reply;
    if (!SendRequest(SandboxManagerInterfaceCode::UNPERSIST_PERMISSION, data, reply)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "remote fail");
        return SANDBOX_MANAGER_SERVICE_REMOTE_ERR;
    }

    int32_t remoteRet;
    if (!reply.ReadInt32(remoteRet)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read ret fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (remoteRet == SANDBOX_MANAGER_OK && !reply.ReadUInt32Vector(&result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read result fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return remoteRet;
}

int32_t SandboxManagerProxy::setPolicy(uint64_t tokenid, const std::vector<PolicyInfo> &policy,
    uint64_t policyFlag)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (!data.WriteUint64(tokenid)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write tokenid fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    
    PolicyInfoVectorParcel policyInfoVectorParcel;
    policyInfoVectorParcel.policyVector = policy;
    if (!data.WriteParcelable(&policyInfoVectorParcel)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policyInfoVectorParcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (!data.WriteUint64(policyFlag)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policyFlag fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!SendRequest(SandboxManagerInterfaceCode::SET_POLICY, data, reply)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "remote fail");
        return SANDBOX_MANAGER_SERVICE_REMOTE_ERR;
    }

    int32_t remoteRet;
    if (!reply.ReadInt32(remoteRet)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read ret fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return remoteRet;
}

int32_t SandboxManagerProxy::startAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    PolicyInfoVectorParcel policyInfoVectorParcel;
    policyInfoVectorParcel.policyVector = policy;
    if (!data.WriteParcelable(&policyInfoVectorParcel)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policyInfoVectorParcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!SendRequest(SandboxManagerInterfaceCode::START_ACCESSING_URI, data, reply)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "remote fail");
        return SANDBOX_MANAGER_SERVICE_REMOTE_ERR;
    }

    int32_t remoteRet;
    if (!reply.ReadInt32(remoteRet)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read ret fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (remoteRet == SANDBOX_MANAGER_OK && !reply.ReadUInt32Vector(&result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read result fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return remoteRet;
}

int32_t SandboxManagerProxy::stopAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    PolicyInfoVectorParcel policyInfoVectorParcel;
    policyInfoVectorParcel.policyVector = policy;
    if (!data.WriteParcelable(&policyInfoVectorParcel)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policyInfoVectorParcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!SendRequest(SandboxManagerInterfaceCode::STOP_ACCESSING_URI, data, reply)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "remote fail");
        return SANDBOX_MANAGER_SERVICE_REMOTE_ERR;
    }

    int32_t remoteRet;
    if (!reply.ReadInt32(remoteRet)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read ret fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (remoteRet == SANDBOX_MANAGER_OK && !reply.ReadUInt32Vector(&result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read result fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return remoteRet;
}

int32_t SandboxManagerProxy::checkPersistPermission(uint64_t tokenid, const std::vector<PolicyInfo> &policy,
    std::vector<bool> &result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ISandboxManager::GetDescriptor())) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write descriptor fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    if (!data.WriteUint64(tokenid)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write tokenid fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    
    PolicyInfoVectorParcel policyInfoVectorParcel;
    policyInfoVectorParcel.policyVector = policy;
    if (!data.WriteParcelable(&policyInfoVectorParcel)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "Write policyInfoVectorParcel fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!SendRequest(SandboxManagerInterfaceCode::CHECK_PERSIST_PERMISSION, data, reply)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "remote fail");
        return SANDBOX_MANAGER_SERVICE_REMOTE_ERR;
    }

    int32_t remoteRet;
    if (!reply.ReadInt32(remoteRet)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read ret fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }

    if (remoteRet == SANDBOX_MANAGER_OK && !reply.ReadBoolVector(&result)) {
        SANDBOXMANAGER_LOG_ERROR(LABEL, "read result fail");
        return SANDBOX_MANAGER_SERVICE_PARCEL_ERR;
    }
    return remoteRet;
}
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS