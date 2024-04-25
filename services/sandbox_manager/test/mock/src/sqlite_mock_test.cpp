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

#include <gtest/gtest.h>
#include <string>

#define private public
#include "sandbox_manager_db.h"
#include "sqlite_helper.h"
#include "statement.h"
#include "variant_value.h"
#undef private

using namespace testing::ext;
namespace OHOS {
namespace AccessControl {
namespace SandboxManager {
namespace {
static sqlite3 DEFAULT_DB = 0;
static const std::string DEFAULT_SQL = "test";
const unsigned char *DEFAULT_UCHARP = reinterpret_cast<const unsigned char*>(DEFAULT_SQL.c_str());
const char *DEFAULT_CHARP = DEFAULT_SQL.c_str();
}

class SqliteMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    SqliteMocker *sqlMocker_ = nullptr;

    void SetUpDefaultMockSetting();
};

void SqliteMockTest::SetUpTestCase(void)
{}

void SqliteMockTest::TearDownTestCase(void)
{}

void SqliteMockTest::SetUp(void)
{
    sqlMocker_ = &SqliteMocker::GetInstance();
    ASSERT_NE(nullptr, sqlMocker_);
}

void SqliteMockTest::TearDown(void)
{}

void SqliteMockTest::SetUpDefaultMockSetting()
{
    ASSERT_NE(nullptr, sqlMocker_);
    // setup default mock setting
    EXPECT_CALL(*sqlMocker_, sqlite3_open(testing::_, testing::_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_close(testing::_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_exec(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_prepare_v2(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_finalize(testing::_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_bind_text(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_bind_int(testing::_, testing::_, testing::_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_bind_int64(testing::_, testing::_, testing::_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_column_int(testing::_, testing::_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_step(testing::_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_bind_parameter_index(testing::_, testing::_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_reset(testing::_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_column_count(testing::_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_column_type(testing::_, testing::_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_column_int64(testing::_, testing::_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_errmsg(testing::_)).WillRepeatedly(testing::Return(DEFAULT_CHARP));
    EXPECT_CALL(*sqlMocker_, sqlite3_free(testing::_)).Times(testing::AtLeast(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_column_text(testing::_, testing::_))
        .WillRepeatedly(testing::Return(DEFAULT_UCHARP));
    EXPECT_CALL(*sqlMocker_, sqlite3_column_name(testing::_, testing::_))
        .WillRepeatedly(testing::Return(DEFAULT_CHARP));
}

/**
 * @tc.name: SqliteMock001
 * @tc.desc: Test Statement::Bind err branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SqliteMockTest, SqliteMock001, TestSize.Level1)
{
    SetUpDefaultMockSetting();
    EXPECT_CALL(*sqlMocker_, sqlite3_prepare_v2(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(1));
    Statement statement(&DEFAULT_DB, DEFAULT_SQL);

    statement.Bind(-1, "");
    EXPECT_CALL(*sqlMocker_, sqlite3_bind_text(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(SQLITE_OK));
    statement.Bind(1, "");

    int32_t val1 = 0;
    statement.Bind(-1, val1);
    EXPECT_CALL(*sqlMocker_, sqlite3_bind_int(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(SQLITE_OK));
    statement.Bind(1, val1);

    int64_t val2 = 0;
    statement.Bind(-1, val2);
    EXPECT_CALL(*sqlMocker_, sqlite3_bind_int64(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(SQLITE_OK));
    statement.Bind(1, val2);

    EXPECT_CALL(*sqlMocker_, sqlite3_bind_text(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(1));
    statement.Bind(1, "");

    int32_t val3 = 0;
    EXPECT_CALL(*sqlMocker_, sqlite3_bind_int(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(1));
    statement.Bind(1, val3);

    int64_t val4 = 0;
    EXPECT_CALL(*sqlMocker_, sqlite3_bind_int64(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(1));
    statement.Bind(1, val4);
}

/**
 * @tc.name: SqliteMock002
 * @tc.desc: Test Statement::GetColumnInt64
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SqliteMockTest, SqliteMock002, TestSize.Level1)
{
    SetUpDefaultMockSetting();
    EXPECT_CALL(*sqlMocker_, sqlite3_prepare_v2(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(1));
    Statement statement(&DEFAULT_DB, DEFAULT_SQL);

    int64_t ret = 0xff; // test input
    EXPECT_CALL(*sqlMocker_, sqlite3_column_int64(testing::_, testing::_))
        .WillOnce(testing::Return(ret));
    EXPECT_EQ(ret, statement.GetColumnInt64(0));
}

/**
 * @tc.name: SqliteMock003
 * @tc.desc: Test Statement::Step
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SqliteMockTest, SqliteMock003, TestSize.Level1)
{
    SetUpDefaultMockSetting();
    EXPECT_CALL(*sqlMocker_, sqlite3_prepare_v2(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(1));
    Statement statement(&DEFAULT_DB, DEFAULT_SQL);

    EXPECT_CALL(*sqlMocker_, sqlite3_step(testing::_))
        .WillOnce(testing::Return(SQLITE_ROW));
    EXPECT_EQ(Statement::State::ROW, statement.Step());

    EXPECT_CALL(*sqlMocker_, sqlite3_step(testing::_))
        .WillOnce(testing::Return(SQLITE_DONE));
    EXPECT_EQ(Statement::State::DONE, statement.Step());

    EXPECT_CALL(*sqlMocker_, sqlite3_step(testing::_))
        .WillOnce(testing::Return(SQLITE_BUSY));
    EXPECT_EQ(Statement::State::BUSY, statement.Step());

    EXPECT_CALL(*sqlMocker_, sqlite3_step(testing::_))
        .WillOnce(testing::Return(SQLITE_MISUSE));
    EXPECT_EQ(Statement::State::MISUSE, statement.Step());

    EXPECT_CALL(*sqlMocker_, sqlite3_step(testing::_))
        .WillOnce(testing::Return(-1));
    EXPECT_EQ(Statement::State::UNKNOWN, statement.Step());
}

/**
 * @tc.name: SqliteMock004
 * @tc.desc: Test Statement::GetValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SqliteMockTest, SqliteMock004, TestSize.Level1)
{
    SetUpDefaultMockSetting();
    EXPECT_CALL(*sqlMocker_, sqlite3_prepare_v2(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(1));
    Statement statement(&DEFAULT_DB, DEFAULT_SQL);

    EXPECT_CALL(*sqlMocker_, sqlite3_column_type(testing::_, testing::_))
        .WillOnce(testing::Return(SQLITE_INTEGER));
    int64_t ret = 0xff; // test input
    EXPECT_CALL(*sqlMocker_, sqlite3_column_int64(testing::_, testing::_))
        .WillOnce(testing::Return(ret));
    VariantValue val1 = statement.GetValue(0, true);
    EXPECT_EQ(ret, val1.GetInt64());

    EXPECT_CALL(*sqlMocker_, sqlite3_column_type(testing::_, testing::_))
        .WillOnce(testing::Return(-1));
    VariantValue val2 = statement.GetValue(0, true);
    EXPECT_EQ(-1, val2.GetInt64());
}

class SqliteHelperMocker : public SqliteHelper {
public:
    SqliteHelperMocker(std::string dbName, std::string dbPath, int32_t version);
    ~SqliteHelperMocker() = default;

    MOCK_METHOD(void, OnCreate, (), (override));
    MOCK_METHOD(void, OnUpdate, (), (override));
};

SqliteHelperMocker::SqliteHelperMocker(std::string dbName, std::string dbPath, int32_t version)
    : SqliteHelper(dbName, dbPath, version)
{}

/**
 * @tc.name: SqliteMock005
 * @tc.desc: Test SqliteHelper::SetVersion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SqliteMockTest, SqliteMock005, TestSize.Level1)
{
    SetUpDefaultMockSetting();
    EXPECT_CALL(*sqlMocker_, sqlite3_prepare_v2(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(1));
    SqliteHelperMocker mocker("", "", 0);
    mocker.db_ = nullptr;
    mocker.SetVersion();
    mocker.db_ = &DEFAULT_DB;
    mocker.SetVersion();
}

/**
 * @tc.name: SqliteMock006
 * @tc.desc: Test SqliteHelper::GetVersion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SqliteMockTest, SqliteMock006, TestSize.Level1)
{
    SetUpDefaultMockSetting();
    SqliteHelperMocker mocker("", "", 0);
    mocker.db_ = nullptr;
    EXPECT_CALL(*sqlMocker_, sqlite3_prepare_v2(testing::_, testing::_, testing::_, testing::_, testing::_))
        .Times(0);
    mocker.GetVersion();
}

/**
 * @tc.name: SqliteMock007
 * @tc.desc: Test SqliteHelper::ExecuteSql, CommitTransaction, BeginTransaction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SqliteMockTest, SqliteMock007, TestSize.Level1)
{
    SetUpDefaultMockSetting();
    SqliteHelperMocker mocker("", "", 0);
    mocker.db_ = &DEFAULT_DB;
    EXPECT_CALL(*sqlMocker_, sqlite3_exec(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(1));
    EXPECT_CALL(*sqlMocker_, sqlite3_free(testing::_))
        .Times(1);
    mocker.ExecuteSql(DEFAULT_SQL);

    EXPECT_CALL(*sqlMocker_, sqlite3_exec(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(1));
    EXPECT_CALL(*sqlMocker_, sqlite3_free(testing::_))
        .Times(1);
    mocker.CommitTransaction();

    EXPECT_CALL(*sqlMocker_, sqlite3_exec(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(1));
    EXPECT_CALL(*sqlMocker_, sqlite3_free(testing::_))
        .Times(1);
    mocker.BeginTransaction();
}

/**
 * @tc.name: SqliteMock008
 * @tc.desc: Test SqliteHelper::Close
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SqliteMockTest, SqliteMock008, TestSize.Level1)
{
    SetUpDefaultMockSetting();
    SqliteHelperMocker mocker("", "", 0);
    mocker.db_ = &DEFAULT_DB;
    EXPECT_CALL(*sqlMocker_, sqlite3_close(testing::_))
        .WillOnce(testing::Return(1));
    mocker.Close();
}

/**
 * @tc.name: SqliteMock009
 * @tc.desc: Test SqliteHelper::Close
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SqliteMockTest, SqliteMock009, TestSize.Level1)
{
    SetUpDefaultMockSetting();
    SqliteHelperMocker mocker1("", "", 0);
    EXPECT_CALL(*sqlMocker_, sqlite3_open(testing::_, testing::_))
        .Times(0);
    mocker1.Open();

    SqliteHelperMocker mocker2("test", "", 0);
    mocker2.Open();

    SqliteHelperMocker mocker3("test", "test", -1);
    mocker3.Open();

    mocker3.currentVersion_ = 0xff; // random test num
    EXPECT_CALL(*sqlMocker_, sqlite3_open(testing::_, testing::_))
        .WillOnce(testing::Return(1));
    mocker3.Open();
}

/**
 * @tc.name: SqliteMock010
 * @tc.desc: Test SqliteHelper::Close
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SqliteMockTest, SqliteMock010, TestSize.Level1)
{
    SetUpDefaultMockSetting();
    SqliteHelperMocker mocker4("test", "test", 0xff);
    EXPECT_CALL(*sqlMocker_, sqlite3_open(testing::_, testing::_))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(&DEFAULT_DB), testing::Return(0)));
    EXPECT_CALL(*sqlMocker_, sqlite3_column_int(testing::_, testing::_)).Times(testing::AnyNumber())
        .WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*sqlMocker_, sqlite3_step(testing::_)).Times(testing::AnyNumber())
        .WillOnce(testing::Return(SQLITE_ROW)).WillRepeatedly(testing::Return(SQLITE_BUSY));
    EXPECT_CALL(mocker4, OnCreate()).Times(1); // call OnCreate
    EXPECT_CALL(mocker4, OnUpdate()).Times(0);
    mocker4.Open();
}

/**
 * @tc.name: SqliteMock011
 * @tc.desc: Test SqliteHelper::Close
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SqliteMockTest, SqliteMock011, TestSize.Level1)
{
    SetUpDefaultMockSetting();
    SqliteHelperMocker mocker5("test", "test", 0xff);
    EXPECT_CALL(*sqlMocker_, sqlite3_step(testing::_)).Times(testing::AnyNumber())
        .WillOnce(testing::Return(SQLITE_ROW)).WillRepeatedly(testing::Return(SQLITE_BUSY));
    EXPECT_CALL(*sqlMocker_, sqlite3_open(testing::_, testing::_))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(&DEFAULT_DB), testing::Return(0)));
    EXPECT_CALL(*sqlMocker_, sqlite3_column_int(testing::_, testing::_)).Times(testing::AnyNumber())
        .WillOnce(testing::Return(1));
    EXPECT_CALL(mocker5, OnCreate()).Times(0); // not call OnCreate
    EXPECT_CALL(mocker5, OnUpdate()).Times(1); // call OnUpdate
    mocker5.Open();
}

/**
 * @tc.name: SqliteMock012
 * @tc.desc: Test SqliteHelper::Close
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SqliteMockTest, SqliteMock012, TestSize.Level1)
{
    SetUpDefaultMockSetting();
    SqliteHelperMocker mocker6("test", "test", 1);
    EXPECT_CALL(*sqlMocker_, sqlite3_step(testing::_)).Times(testing::AnyNumber())
        .WillOnce(testing::Return(SQLITE_ROW)).WillRepeatedly(testing::Return(SQLITE_BUSY));
    EXPECT_CALL(*sqlMocker_, sqlite3_open(testing::_, testing::_))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(&DEFAULT_DB), testing::Return(0)));
    EXPECT_CALL(*sqlMocker_, sqlite3_column_int(testing::_, testing::_)).Times(testing::AnyNumber())
        .WillOnce(testing::Return(2)); // test: version > currentVersion_
    EXPECT_CALL(mocker6, OnCreate()).Times(0); // not call OnCreate
    EXPECT_CALL(mocker6, OnUpdate()).Times(0); // not call OnUpdate
    mocker6.Open();
}

/**
 * @tc.name: SqliteMock013
 * @tc.desc: Test SandboxManagerDb::Add
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SqliteMockTest, SqliteMock013, TestSize.Level1)
{
    SetUpDefaultMockSetting();
    EXPECT_CALL(*sqlMocker_, sqlite3_step(testing::_)).Times(testing::AnyNumber())
        .WillOnce(testing::Return(SQLITE_ROW)).WillRepeatedly(testing::Return(SQLITE_BUSY));
    GenericValues val;
    val.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(1));
    val.Put(PolicyFiledConst::FIELD_PATH, "/user_grant/a");
    val.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(0b01));
    val.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(2)); // 2 means '/' included in path
    val.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));

    std::vector<GenericValues> values = {val};
    EXPECT_EQ(SandboxManagerDb::ExecuteResult::FAILURE, SandboxManagerDb::GetInstance().Add(
        SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, values));
}

/**
 * @tc.name: SqliteMock014
 * @tc.desc: Test SandboxManagerDb::RefreshAll
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SqliteMockTest, SqliteMock014, TestSize.Level1)
{
    SetUpDefaultMockSetting();
    EXPECT_CALL(*sqlMocker_, sqlite3_step(testing::_)).Times(testing::AnyNumber())
        .WillOnce(testing::Return(SQLITE_DONE)).WillOnce(testing::Return(SQLITE_ROW))
        .WillRepeatedly(testing::Return(SQLITE_BUSY));
    GenericValues val;
    val.Put(PolicyFiledConst::FIELD_TOKENID, static_cast<int64_t>(1));
    val.Put(PolicyFiledConst::FIELD_PATH, "/user_grant/a");
    val.Put(PolicyFiledConst::FIELD_MODE, static_cast<int64_t>(0b01));
    val.Put(PolicyFiledConst::FIELD_DEPTH, static_cast<int64_t>(2)); // 2 means '/' included in path
    val.Put(PolicyFiledConst::FIELD_FLAG, static_cast<int64_t>(0));

    std::vector<GenericValues> values = {val};
    EXPECT_EQ(SandboxManagerDb::ExecuteResult::FAILURE, SandboxManagerDb::GetInstance().RefreshAll(
        SandboxManagerDb::SANDBOX_MANAGER_PERSISTED_POLICY, values));
}
} // SandboxManager
} // AccessControl
} // OHOS