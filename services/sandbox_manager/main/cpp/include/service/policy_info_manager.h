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

#ifndef POLICY_INFO_MANAGER_H
#define POLICY_INFO_MANAGER_H

#include <cstdint>
#include <string>
#include <vector>
#include "generic_values.h"
#include "policy_info.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {

class PolicyInfoManager {
public:
    static PolicyInfoManager &GetInstance();
    PolicyInfoManager() = default;
    virtual ~PolicyInfoManager() = default;
    void Init();
    /**
     * @brief Insert policys to database
     * @param tokenId token id of the object
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result insert result of each policy
     * @return SANDBOX_MANAGER_DB_ERR / SANDBOX_MANAGER_OK
     */
    int32_t AddPolicy(const uint64_t tokenId, const std::vector<PolicyInfo> &policy,
        std::vector<uint32_t> &result, const uint32_t flag = 0);
    /**
     * @brief Match policys of a certain tokenId
     * @param tokenId token id of the object
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result match result of each policy
     * @return SANDBOX_MANAGER_DB_ERR / SANDBOX_MANAGER_OK
     */
    int32_t MatchPolicy(const uint64_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    /**
     * @brief Match one policy of a certain tokenId
     * @param tokenId token id of the object
     * @param policy PolicyInfo, see policy_info.h
     * @param result match result of each policy
     * @return INVALID_PARAMTER / SANDBOX_MANAGER_DB_ERR
     *     / SANDBOX_MANAGER_POLICY_NOT_MATCH / SANDBOX_MANAGER_OK
     */
    int32_t MatchSinglePolicy(const uint64_t tokenId, const PolicyInfo &policy, uint32_t &result);
    /**
     * @brief remove policys of a certain tokenId
     * @param tokenId token id of the object
     * @param policy vector of PolicyInfo, see policy_info.h
     * @param result  remove result of each policy
     * @return INVALID_PARAMTER / SANDBOX_MANAGER_DB_ERR / SANDBOX_MANAGER_OK
     *      / SANDBOX_MANAGER_DB_RETURN_EMPTY
     */
    int32_t RemovePolicy(const uint64_t tokenId, const std::vector<PolicyInfo> &policy, std::vector<uint32_t> &result);
    /**
     * @brief remove all policys of a certain tokenId (bundle)
     * @param tokenId token id of the object
     * @return bool
     */
    bool RemoveBundlePolicy(const uint64_t tokenId);
 
private:
    /**
     * @brief find a record with same token and policy path (mode not inclued)
     * @param tokenId token id of the object
     * @param policy search policy
     * @param result search result
     * @return SANDBOX_MANAGER_DB_ERR / SANDBOX_MANAGER_DB_RETURN_EMPTY / SANDBOX_MANAGER_OK
     */
    int32_t ExactFind(const uint64_t tokenId,  const PolicyInfo &policy, PolicyInfo &result);
    /**
     * @brief find a record with input conditions
     * @param conditions input conditions
     * @param symbols input symbols of conditions, like depthColumn <= 2, 2 in condition, <= in symbols
     * @param results search result
     * @return SANDBOX_MANAGER_DB_ERR / SANDBOX_MANAGER_DB_RETURN_EMPTY / SANDBOX_MANAGER_OK
     */
    int32_t RangeFind(const GenericValues &conditions, const GenericValues &symbols,
        std::vector<GenericValues> &results);
    /**
     * @brief transfer a policy and token to GenericValues style
     * @param tokenId token id of the object
     * @param policy input policy
     * @param generic transfer result
     * @return
     */
    void TransferPolicyToGeneric(const uint64_t tokenId, const PolicyInfo &policy, GenericValues &generic);
    /**
     * @brief cal depth of a given path string
     * @param path path of file system
     * @return depth of a path: "/" = 0, "/a" = 1, "/a/b" = 2
     */
    int64_t GetDepth(const std::string &path);
    /**
     * @brief judge two polict whether match
     * @param searchPolicy input policy
     * @param searchDepth depth of input policy
     * @param referPolicy refer policy
     * @param referDepth depth of refer policy
     * @return true / false
     */
    bool IsPolicyMatch(const PolicyInfo &searchPolicy, const uint64_t searchDepth,
        const PolicyInfo &referPolicy, const uint64_t referDepth);
    /**
     * @brief remove the end '/' of a file path
     * @param path input path
     * @return
     */
    std::string AdjustPath(const std::string &path);
    /**
     * @brief check policy validity
     * @param policy input policy, see policy_info.h
     * @return INVALID_PATH / INVALID_MODE / SANDBOX_MANAGER_OK
     */
    int32_t CheckPolicyValidity(const PolicyInfo &policy);
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // POLICY_INFO_MANAGER_H