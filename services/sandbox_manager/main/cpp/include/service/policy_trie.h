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

#ifndef POLICY_TRIE_H
#define POLICY_TRIE_H

#include <cstdint>
#include <set>
#include <stack>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

class PolicyTrie {
public:
    enum CheckState {
        INIT = 0,
        ALLOWED,
        NOT_ALLOWED,
    };

    PolicyTrie() {}
    ~PolicyTrie() { DeleteChildren(); }
    PolicyTrie(const PolicyTrie&) = delete;
    PolicyTrie &operator=(const PolicyTrie&) = delete;
    PolicyTrie(PolicyTrie&&) = delete;
    PolicyTrie &operator=(PolicyTrie&&) = delete;

    void Clear();
    void InsertPath(const std::string &path, uint64_t mode, bool preserveCase = false);
    void InsertPreservingCase(const std::string &path, uint64_t mode);
    bool CheckPath(const std::string &path);
    bool CheckPath(const std::string &path, uint64_t mode);
    bool CheckPathNew(const std::string &path, uint64_t mode);
    std::vector<std::string> FindMatchingPaths(const std::string &path, uint64_t mode);
    void SetCasePolicy(const std::string &path, bool caseInsensitive);
    void SetInsensitive(const std::string &path);
    void SetSensitive(const std::string &path);
    bool AddDeniedPaths(const std::vector<std::string> &paths);
    bool IsEmpty() const;
    static std::vector<std::string> SplitPath(const std::string &path);
private:
    inline static const uint64_t MODE_FILTER = 0b11111;
    struct MatchChain {
        PolicyTrie *node;
        std::string path;
    };
    struct MatchCandidate {
        const std::string *key;
        PolicyTrie *child;
    };
    // Extends every chain by one segment, forking one chain per stored case variant at
    // case-insensitive levels.
    void AdvanceMatchChains(const std::string &segment,
        std::vector<MatchChain> &chains, std::vector<MatchChain> &next);
    // Appends the children of this node whose key matches the segment: case-sensitive
    // nodes contribute their exact child, case-insensitive nodes all stored variants.
    void CollectMatchCandidates(const std::string &segment,
        std::vector<MatchCandidate> &candidates) const;
    bool IsPolicyMatch(uint64_t referMode, uint64_t searchMode);
    bool CheckPathInternal(const std::string &path, uint64_t mode, bool checkMode = true);
    bool CheckPathInternalNew(const std::string &path, uint64_t mode, bool checkMode = true);
    void DeleteChildren();
    static const std::unordered_map<std::string, int> DENIED_PATHS;
    std::unordered_map<std::string, PolicyTrie *> children_;
    bool isEndOfPath_ = false;
    bool caseInsensitive_ = false;
    bool denyInherit_ = false;  // Mark nodes that require needLevel enforcement
    std::unordered_map<std::string, std::unordered_set<std::string>> indexMap_;
    uint64_t mode_ = 0;
    std::set<uint64_t> modes_;
};

#endif