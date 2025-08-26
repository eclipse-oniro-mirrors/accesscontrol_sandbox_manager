/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef DEC_TEST_H
#define DEC_TEST_H

#ifdef DEC_ENABLED
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <memory.h>
#include <sys/mount.h>

#include <filesystem>
#include <errno.h>
#include <iostream>
#include <getopt.h>
#include <dirent.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <securec.h>

#define MAX_POLICY_NUM 8
#define DEC_POLICY_HEADER_RESERVED 64

#define HM_DEC_IOCTL_BASE 's'
#define HM_SET_POLICY_ID 1
#define HM_DEL_POLICY_ID 2
#define HM_QUERY_POLICY_ID 3
#define HM_CHECK_POLICY_ID 4
#define HM_DESTORY_POLICY_ID 5
#define HM_CONSTRAINT_POLICY_ID 6
#define HM_DEL_POLICY_BY_USER_ID 7
#define SET_DEC_RULE_CMD _IOWR(HM_DEC_IOCTL_BASE, HM_SET_POLICY_ID, struct dec_rule_s)
#define DEL_DEC_RULE_CMD _IOWR(HM_DEC_IOCTL_BASE, HM_DEL_POLICY_ID, struct dec_rule_s)
#define QUERY_DEC_RULE_CMD _IOWR(HM_DEC_IOCTL_BASE, HM_QUERY_POLICY_ID, struct dec_rule_s)
#define CHECK_DEC_RULE_CMD _IOWR(HM_DEC_IOCTL_BASE, HM_CHECK_POLICY_ID, struct dec_rule_s)
#define DESTORY_DEC_RULE_CMD _IOWR(HM_DEC_IOCTL_BASE, HM_DESTORY_POLICY_ID, struct dec_rule_s)
#define CONSTRAINT_DEC_RULE_CMD _IOW(HM_DEC_IOCTL_BASE, HM_CONSTRAINT_POLICY_ID, struct dec_rule_s)
#define DEL_DEC_RULE_BY_USER_CMD _IOWR(HM_DEC_IOCTL_BASE, HM_DEL_POLICY_BY_USER_ID, struct dec_rule_s)

#define DEC_MODE_READ 1
#define DEC_MODE_WRITE 2
#define DEC_MODE_RW 3

struct path_info {
    char *path;
    uint32_t path_len;
    uint32_t mode;
    bool ret_flag;
    path_info() : path(NULL), path_len(0), mode(0), ret_flag(false) {}

    path_info(const char *_path) : mode(0)
    {
        path = (char *)malloc(strlen(_path) + 1);
        (void)memcpy_s(path, strlen(_path), _path, strlen(_path));
        path_len = strlen(_path);
    }
    path_info(const char *_path, uint32_t _mode) : mode(_mode)
    {
        path = (char *)malloc(strlen(_path) + 1);
        (void)memcpy_s(path, strlen(_path), _path, strlen(_path));
        path_len = strlen(_path);
    }
    ~path_info()
    {
        if (path != NULL) {
            free(path);
            path = NULL;
        }
    }
    path_info(const path_info &other)
    {
        path = (char *)malloc(strlen(other.path) + 1);
        (void)memcpy_s(path, strlen(other.path), other.path, strlen(other.path));
        path_len = other.path_len;
        mode = other.mode;
        ret_flag = other.ret_flag;
    }
    path_info &operator=(const path_info &other)
    {
        path = (char *)malloc(strlen(other.path) + 1);
        (void)memcpy_s(path, strlen(other.path), other.path, strlen(other.path));
        path_len = other.path_len;
        mode = other.mode;
        ret_flag = other.ret_flag;
        return *this;
    }
};

struct dec_rule_s {
    uint64_t tokenId;
    uint64_t timeStamp;
    struct path_info path[MAX_POLICY_NUM];
    uint32_t pathNum;
    int32_t userId;
    uint64_t reserved[DEC_POLICY_HEADER_RESERVED];
    bool persistFlag;
    dec_rule_s() : timeStamp(0), pathNum(0), userId(0), persistFlag(false) {}
    void addPath(const char *path_, uint32_t mode_ = 0)
    {
        struct path_info pathInfo(path_, mode_);
        path[pathNum] = pathInfo;
        pathNum++;
    }
};

int ConstraintPath(const std::string &path);
int SetPath(uint64_t tokenid, const std::string &path, uint32_t mode, bool persistFlag,
    uint64_t timestamp, int32_t userId);
int CheckPath(uint64_t tokenid, const std::string &path, uint32_t mode);
int TestWrite(uint64_t tokenid, const std::string &fileName, int32_t uid = 0, int32_t gid = 0);
int TestRead(uint64_t tokenid, const std::string &fileName, int32_t uid = 0, int32_t gid = 0);
int TestCopy(uint64_t tokenid, const std::string &srcPath, const std::string &dstPath,
    int32_t uid = 0, int32_t gid = 0);
int Mkdir(uint64_t tokenid, std::string path, int32_t uid = 0, int32_t gid = 0);
int TestRename(uint64_t tokenid, const std::string &fileName, int32_t uid = 0, int32_t gid = 0);
int TestRemove(uint64_t tokenid, const std::string &fileName, int32_t uid = 0, int32_t gid = 0);
int DestroyByTokenid(uint64_t tokenid, uint64_t timestamp);
int QueryPath(uint64_t tokenid, const std::string &path, uint32_t mode);
int TestAccess(uint64_t tokenid, const std::string &fileName, uint32_t mode, int32_t uid = 0, int32_t gid = 0);
int DeletePath(uint64_t tokenid, const std::string &path, uint64_t timestamp);
int TestReadDir(uint64_t tokenid, const std::string &dirName, int32_t uid = 0, int32_t gid = 0);
int TestRemoveDir(uint64_t tokenid, const std::string &fileName, int32_t uid = 0, int32_t gid = 0);
int DeletePathByUser(int32_t user_id, const std::string &path);
void DecTestClose();
#endif
#endif // DEC_TEST_H