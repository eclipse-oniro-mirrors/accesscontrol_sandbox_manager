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

#ifndef SANDBOXMANAGER_KIT_H
#define SANDBOXMANAGER_KIT_H

#include "policy_info.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
/**
 * @brief Declares SandboxManagerKit class
 */
class SandboxManagerKit {
public:
    /**
     * @brief Persist policys with caller's tokenId
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result insert result of each policy, result is SandboxRetType in policy_info.h
     * @return SandboxManagerErrCode, see sandbox_manager_err_code.h
     */
    static int32_t PersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    /**
     * @brief Unpersist policys with caller's tokenId
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result insert result of each policy, result is SandboxRetType in policy_info.h
     * @return SandboxManagerErrCode, see sandbox_manager_err_code.h
     */
    static int32_t UnPersistPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    /**
     * @brief Persist policys with a given tokenId
     * @param tokenId a given tokenId
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result insert result of each policy, result is SandboxRetType in policy_info.h
     * @return SandboxManagerErrCode, see sandbox_manager_err_code.h
     */
    static int32_t PersistPolicy(
        uint64_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    /**
     * @brief Unpersist policys with a given tokenId
     * @param tokenId a given tokenId
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result insert result of each policy, result is SandboxRetType in policy_info.h
     * @return SandboxManagerErrCode, see sandbox_manager_err_code.h
     */
    static int32_t UnPersistPolicy(
        uint64_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    /**
     * @brief Set policys with a given tokenId to MAC layer
     * @param tokenId a given tokenId
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result insert result of each policy, result is SandboxRetType in policy_info.h
     * @return SandboxManagerErrCode, see sandbox_manager_err_code.h
     */
    static int32_t SetPolicy(uint64_t tokenId, const std::vector<PolicyInfo> &policy, uint64_t policyFlag);
    /**
     * @brief Set existing persisted policys with caller's tokenId to MAC layer
     *        not existed policy would be ignored, but have a return in result
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result insert result of each policy, result is SandboxRetType in policy_info.h
     * @return SandboxManagerErrCode, see sandbox_manager_err_code.h
     */
    static int32_t StartAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    /**
     * @brief Stop existing persisted policys with caller's tokenId to MAC layer
     *        not existed policy would be ignored, but have a return in result
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result insert result of each policy, result is SandboxRetType in policy_info.h
     * @return SandboxManagerErrCode, see sandbox_manager_err_code.h
     */
    static int32_t StopAccessingPolicy(const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    /**
     * @brief check policys whether is persisted
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result true - exist, false - not exist
     * @return SandboxManagerErrCode, see sandbox_manager_err_code.h
     */
    static int32_t CheckPersistPolicy(
        uint64_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<bool> &result);
};
} // SandboxManager
} // AccessControl
} // OHOS
#endif //SANDBOXMANAGER_KIT_H