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

#ifndef POLICY_INFO_H
#define POLICY_INFO_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
struct PolicyInfo final {
public:
    std::string path;
    uint64_t mode;
};

typedef enum SandboxRetType {
    OPERATE_SUCCESSFULLY = 0,
    FORBIDDEN_TO_BE_PERSISTED = 1,
    INVALID_MODE = 2,
    INVALID_PATH = 3,
    POLICY_HAS_NOT_BEEN_PERSISTED = 4,
    POLICY_HAS_BEEN_PERSISTED = 5,
} SandboxRetType;

const uint32_t IS_POLICY_ALLOWED_TO_BE_PRESISTED = 1 << 0;

typedef enum OperateMode {
    READ_MODE = 1 << 0,
    WRITE_MODE = 1 << 1,
} OperateMode;
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // POLICY_INFO_H