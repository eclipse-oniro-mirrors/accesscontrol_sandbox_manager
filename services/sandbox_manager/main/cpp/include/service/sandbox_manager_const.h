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

#ifndef SANDBOX_MANAGER_CONST_H
#define SANDBOX_MANAGER_CONST_H
#include <string>

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
#define SA_LIFE_TIME (1000 * 60 * 3)   // 3 min

const uint32_t POLICY_PATH_LIMIT = 256;

const uint64_t MODE_FILTER = 0b11;
// 1bit-readbit 2bit- writebit, see OperateMode

const std::string SET_POLICY_PERMISSION_NAME = "ohos.permission.SET_SANDBOX_POLICY";
const std::string ACCESS_PERSIST_PERMISSION_NAME = "ohos.permission.FILE_ACCESS_PERSIST";

const uint32_t POLICY_VECTOR_SIZE_LIMIT = 500;

const std::string DESKTOP_PATH = "/storage/Users/currentUser/Desktop";
const std::string DOWNLOAD_PATH = "/storage/Users/currentUser/Download";
const std::string DOCUMENT_PATH = "/storage/Users/currentUser/Documents";
const std::string DESKTOP_PERMISSION_NAME = "ohos.permission.READ_WRITE_DESKTOP_DIRECTORY";
const std::string DOWNLOAD_PERMISSION_NAME = "ohos.permission.READ_WRITE_DOWNLOAD_DIRECTORY";
const std::string DOCUMENT_PERMISSION_NAME = "ohos.permission.READ_WRITE_DOCUMENTS_DIRECTORY";

} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // SANDBOX_MANAGER_CONST_H