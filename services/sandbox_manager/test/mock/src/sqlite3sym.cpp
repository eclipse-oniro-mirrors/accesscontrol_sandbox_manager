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
#include "sqlite3sym.h"

namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
SqliteMocker &SqliteMocker::GetInstance()
{
    static SqliteMocker instance;
    return instance;
}

int32_t sqlite3_open(const char *filename, sqlite3 **ppDb)
{
    return SqliteMocker::GetInstance().sqlite3_open(filename, ppDb);
}

int32_t sqlite3_close(sqlite3 *db)
{
    return SqliteMocker::GetInstance().sqlite3_close(db);
}

int32_t sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void*, int, char**, char**), void *p, char **errmsg)
{
    return SqliteMocker::GetInstance().sqlite3_exec(db, sql, callback, p, errmsg);
}

int32_t sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail)
{
    return SqliteMocker::GetInstance().sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
}

int32_t sqlite3_finalize(sqlite3_stmt *pStmt)
{
    return SqliteMocker::GetInstance().sqlite3_finalize(pStmt);
}

int32_t sqlite3_bind_text(sqlite3_stmt *pStmt, int i, const char *zData, int nData, void (*xDel)(void*))
{
    return SqliteMocker::GetInstance().sqlite3_bind_text(pStmt, i, zData, nData, xDel);
}

int32_t sqlite3_bind_int(sqlite3_stmt *p, int i, int iValue)
{
    return SqliteMocker::GetInstance().sqlite3_bind_int(p, i, iValue);
}

int32_t sqlite3_bind_int64(sqlite3_stmt *pStmt, int i, sqlite_int64 iValue)
{
    return SqliteMocker::GetInstance().sqlite3_bind_int64(pStmt, i, iValue);
}

int32_t sqlite3_column_int(sqlite3_stmt *pStmt, int i)
{
    return SqliteMocker::GetInstance().sqlite3_column_int(pStmt, i);
}

int32_t sqlite3_step(sqlite3_stmt *pStmt)
{
    return SqliteMocker::GetInstance().sqlite3_step(pStmt);
}

int32_t sqlite3_bind_parameter_index(sqlite3_stmt *pStmt, const char *zName)
{
    return SqliteMocker::GetInstance().sqlite3_bind_parameter_index(pStmt, zName);
}

int32_t sqlite3_reset(sqlite3_stmt *pStmt)
{
    return SqliteMocker::GetInstance().sqlite3_reset(pStmt);
}

int32_t sqlite3_column_count(sqlite3_stmt *pStmt)
{
    return SqliteMocker::GetInstance().sqlite3_column_count(pStmt);
}

int32_t sqlite3_column_type(sqlite3_stmt *pStmt, int i)
{
    return SqliteMocker::GetInstance().sqlite3_column_type(pStmt, i);
}

int64_t sqlite3_column_int64(sqlite3_stmt *pStmt, int i)
{
    return SqliteMocker::GetInstance().sqlite3_column_int64(pStmt, i);
}

const char* sqlite3_errmsg(sqlite3 *db)
{
    return SqliteMocker::GetInstance().sqlite3_errmsg(db);
}

void sqlite3_free(void *p)
{
    return SqliteMocker::GetInstance().sqlite3_free(p);
}

const unsigned char *sqlite3_column_text(sqlite3_stmt *pStmt, int iCol)
{
    return SqliteMocker::GetInstance().sqlite3_column_text(pStmt, iCol);
}

const char *sqlite3_column_name(sqlite3_stmt *pStmt, int n)
{
    return SqliteMocker::GetInstance().sqlite3_column_name(pStmt, n);
}

} // namespace SandboxManager
} // namespace AccessControl
} // namespace OHOS