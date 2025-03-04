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

#ifndef POLICY_INFO_PARCEL_VECTOR_H
#define POLICY_INFO_PARCEL_VECTOR_H
#include <vector>
#include "parcel.h"
#include "policy_info.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
struct PolicyInfoVectorParcel final : public Parcelable {
    PolicyInfoVectorParcel() = default;
    ~PolicyInfoVectorParcel() = default;
    bool Marshalling(Parcel &out) const override;
    static PolicyInfoVectorParcel* Unmarshalling(Parcel &in);
    std::vector<PolicyInfo> policyVector;
};
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // POLICY_INFO_PARCEL_VECTOR_H