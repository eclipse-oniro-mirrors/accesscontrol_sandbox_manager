/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SQLITE3SYM_H
#define SQLITE3SYM_H
#include <gmock/gmock.h>

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
static const int32_t SQLITE_OK = 0;
static void (*SQLITE_TRANSIENT)(void *) = nullptr;


typedef int32_t sqlite3;
typedef int32_t sqlite3_stmt;
typedef int64_t sqlite_int64;

enum SqliteEnum {
    SQLITE_ROW,
    SQLITE_DONE,
    SQLITE_BUSY,
    SQLITE_MISUSE,
    SQLITE_INTEGER,
    SQLITE_TEXT,
};

class SqliteMockInterface {
public:
    virtual int32_t sqlite3_open(const char *filename, sqlite3 **ppDb);
    virtual int32_t sqlite3_close(sqlite3 *db);
    virtual int32_t sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void*, int, char**, char**),
        void *p, char **errmsg);
    virtual int32_t sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt,
        const char **pzTail);
    virtual int32_t sqlite3_finalize(sqlite3_stmt *pStmt);
    virtual int32_t sqlite3_bind_text(sqlite3_stmt *pStmt, int i, const char *zData, int nData,
        void (*xDel)(void *));
    virtual int32_t sqlite3_bind_int(sqlite3_stmt *p, int i, int iValue);
    virtual int32_t sqlite3_bind_int64(sqlite3_stmt *pStmt, int i, sqlite_int64 iValue);
    virtual int32_t sqlite3_column_int(sqlite3_stmt *pStmt, int i);
    virtual int32_t sqlite3_step(sqlite3_stmt *pStmt);
    virtual int32_t sqlite3_bind_parameter_index(sqlite3_stmt *pStmt, const char *zName);
    virtual int32_t sqlite3_reset(sqlite3_stmt *pStmt);
    virtual int32_t sqlite3_column_count(sqlite3_stmt *pStmt);
    virtual int32_t sqlite3_column_type(sqlite3_stmt *pStmt, int i);
    virtual int64_t sqlite3_column_int64(sqlite3_stmt *pStmt, int i);
    virtual const char* sqlite3_errmsg(sqlite3 *db);
    virtual void sqlite3_free(void *p);
    virtual const unsigned char *sqlite3_column_text(sqlite3_stmt *pStmt, int iCol);
    virtual const char *sqlite3_column_name(sqlite3_stmt *pStmt, int N);
};

class SqliteMocker : public SqliteMockInterface {
public:
    SqliteMocker() = default;
    virtual ~SqliteMocker() = default;
    static SqliteMocker &GetInstance();
    MOCK_METHOD(int32_t, sqlite3_open, (const char *, sqlite3 **), (override));
    MOCK_METHOD(int32_t, sqlite3_close, (sqlite3 *), (override));
    MOCK_METHOD(int32_t, sqlite3_exec, (sqlite3 *, const char *,
        int (*)(void*, int, char**, char**), void *, char **), (override));
    MOCK_METHOD(int32_t, sqlite3_prepare_v2, (sqlite3 *, const char *, int,
        sqlite3_stmt **, const char **), (override));
    MOCK_METHOD(int32_t, sqlite3_finalize, (sqlite3_stmt *), (override));
    MOCK_METHOD(int32_t, sqlite3_bind_text, (sqlite3_stmt *, int, const char *,
        int, void (*)(void*)), (override));
    MOCK_METHOD(int32_t, sqlite3_bind_int, (sqlite3_stmt *, int, int), (override));
    MOCK_METHOD(int32_t, sqlite3_bind_int64, (sqlite3_stmt *, int,
        sqlite_int64), (override));
    MOCK_METHOD(int32_t, sqlite3_column_int, (sqlite3_stmt *, int), (override));
    MOCK_METHOD(int32_t, sqlite3_step, (sqlite3_stmt *), (override));
    MOCK_METHOD(int32_t, sqlite3_bind_parameter_index, (sqlite3_stmt *,
        const char *), (override));
    MOCK_METHOD(int32_t, sqlite3_reset, (sqlite3_stmt *), (override));
    MOCK_METHOD(int32_t, sqlite3_column_count, (sqlite3_stmt *), (override));
    MOCK_METHOD(int32_t, sqlite3_column_type, (sqlite3_stmt *, int), (override));
    MOCK_METHOD(int64_t, sqlite3_column_int64, (sqlite3_stmt *, int), (override));
    MOCK_METHOD(const char*, sqlite3_errmsg, (sqlite3*), (override));
    MOCK_METHOD(void, sqlite3_free, (void*), (override));
    MOCK_METHOD(const unsigned char *, sqlite3_column_text, (sqlite3_stmt*, int), (override));
    MOCK_METHOD(const char *, sqlite3_column_name, (sqlite3_stmt *, int), (override));
};

int32_t sqlite3_open(const char *filename, sqlite3 **ppDb);
int32_t sqlite3_close(sqlite3 *db);
int32_t sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void*, int, char**, char**),
    void *p, char **errmsg);
int32_t sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt,
    const char **pzTail);
int32_t sqlite3_finalize(sqlite3_stmt *pStmt);
int32_t sqlite3_bind_text(sqlite3_stmt *pStmt, int i, const char *zData, int nData,
    void (*xDel)(void*));
int32_t sqlite3_bind_int(sqlite3_stmt *p, int i, int iValue);
int32_t sqlite3_bind_int64(sqlite3_stmt *pStmt, int i, sqlite_int64 iValue);
int32_t sqlite3_column_int(sqlite3_stmt *pStmt, int i);
int32_t sqlite3_step(sqlite3_stmt *pStmt);
int32_t sqlite3_bind_parameter_index(sqlite3_stmt *pStmt, const char *zName);
int32_t sqlite3_reset(sqlite3_stmt *pStmt);
int32_t sqlite3_column_count(sqlite3_stmt *pStmt);
int32_t sqlite3_column_type(sqlite3_stmt *pStmt, int i);
int64_t sqlite3_column_int64(sqlite3_stmt *pStmt, int i);
const char* sqlite3_errmsg(sqlite3 *db);
void sqlite3_free(void *p);
const unsigned char *sqlite3_column_text(sqlite3_stmt *pStmt, int iCol);
const char *sqlite3_column_name(sqlite3_stmt *pStmt, int N);
} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS
#endif // SQLITE3SYM_H