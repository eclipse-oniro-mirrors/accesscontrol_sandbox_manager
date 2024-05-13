# 沙箱管理服务

## 简介

沙箱管理服务是OpenHarmony提供的系统服务之一。该服务负责应用沙箱间文件共享规则的管理和持久化等事务。

应用沙箱目录隔离会影响应用间的文件共享操作。为了对合法的应用间文件共享规则进行持久化管理，新增沙箱管理部件以支持共享文件读写规则的持久化存储、管理、激活操作。

沙箱管理模块主要提供以下功能：

1、持久化规则存储

2、持久化规则管理

3、临时/持久化规则设置与激活

4、提供相应innerapi

## 目录

```
/base/accesscontrol/sandbox_manager
├── config                      # 覆盖率设置目录
├── frameworks                  # 框架层，基础功能代码存放目录
│   ├── common                  # 框架公共代码存放目录
│   ├── sandbox_manager         # 沙箱管理服务框架代码存放目录
│   └── test                    # 测试代码存放目录
├── interfaces/innerkits/       # 接口层
│   └── sandbox_manager         # 沙箱管理接口代码存放目录
└── services                    # 服务层
    ├── common                  # 服务公共代码存放目录
    └── sandbox_manager
        └── main                # 沙箱管理服务侧代码存放目录

```

## 使用
### 接口说明

| **接口申明** | **接口描述** |
| --- | --- |
| int32_t PersistPolicy(const std::vector\<PolicyInfo\> &policy, std::vector<uint32_t> &result); | 添加调用者持久化规则 |
| int32_t UnPersistPolicy(const std::vector\<PolicyInfo\> &policy, std::vector<uint32_t> &result); | 删除调用者持久化规则 |
| int32_t PersistPolicy(uint64_t tokenId, const std::vector\<PolicyInfo\> &policy, std::vector<uint32_t> &result);| 添加指定tokenId的持久化规则 |
| int32_t UnPersistPolicy(uint64_t tokenId, const std::vector\<PolicyInfo\> &policy, std::vector<uint32_t> &result);| 删除指定tokenId的持久化规则 |
| int32_t SetPolicy(uint64_t tokenId, const std::vector\<PolicyInfo\> &policy, uint64_t policyFlag); | 设置临时规则 |
|int32_t StartAccessingPolicy(const std::vector\<PolicyInfo\> &policy, std::vector<uint32_t> &result);| 激活持久化规则 |
|int32_t StopAccessingPolicy(const std::vector\<PolicyInfo\> &policy, std::vector<uint32_t> &result);| 取消激活持久化规则 |
|int32_t CheckPersistPolicy(uint64_t tokenId, const std::vector\<PolicyInfo\> &policy, std::vector<bool> &result);| 校验规则是否已持久化 |

### 限制与约束
1、SetPolicy接口调用者须具有ohos.permission.SET_SANDBOX_POLICY权限，权限定义详见access_token仓

2、除SetPolicy、CheckPersistPolicy接口外，其余接口调用者需具有ohos.permission.FILE_ACCESS_PERSIST权限，权限定义详见access_token仓

3、所有接口中，vector的大小上限为500

## 相关仓

**[filemanagement\_app\_file\_service](https://gitee.com/openharmony/filemanagement_app_file_service/blob/master/README_ZH.md)**

**[ability\_ability\_runtime](https://gitee.com/openharmony/ability_ability_runtime/blob/master/README_zh.md)**
