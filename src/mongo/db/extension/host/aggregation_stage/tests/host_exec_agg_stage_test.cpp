/**
 *    Copyright (C) 2025-present MongoDB, Inc.
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the Server Side Public License, version 1,
 *    as published by MongoDB, Inc.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    Server Side Public License for more details.
 *
 *    You should have received a copy of the Server Side Public License
 *    along with this program. If not, see
 *    <http://www.mongodb.com/licensing/server-side-public-license>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the Server Side Public License in all respects for
 *    all of the code used other than as permitted herein. If you modify file(s)
 *    with this exception, you may extend this exception to your version of the
 *    file(s), but you are not obligated to do so. If you do not wish to do so,
 *    delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */

#include "mongo/db/exec/agg/document_source_to_stage_registry.h"
#include "mongo/db/exec/agg/stage.h"
#include "mongo/db/extension/host/aggregation_stage/executable_agg_stage.h"
#include "mongo/db/extension/host_connector/executable_agg_stage.h"
#include "mongo/db/extension/host_connector/executable_agg_stage_adapter.h"
#include "mongo/db/extension/sdk/aggregation_stage.h"
#include "mongo/db/extension/shared/get_next_result.h"
#include "mongo/db/pipeline/document_source.h"
#include "mongo/db/pipeline/document_source_match.h"
#include "mongo/db/pipeline/document_source_mock.h"
#include "mongo/db/pipeline/expression_context_for_test.h"
#include "mongo/unittest/death_test.h"
#include "mongo/unittest/unittest.h"

#include <memory>

namespace mongo::extension {

namespace {

class ExecAggStageTest : public unittest::Test {
protected:
    ExecAggStageTest() = default;
};

class NoOpHostExecAggStage : public host::ExecAggStage {
public:
    explicit NoOpHostExecAggStage(std::unique_ptr<mongo::exec::agg::Stage> execAggStage)
        : host::ExecAggStage(std::move(execAggStage)) {}

    static inline std::unique_ptr<host::ExecAggStage> make(
        std::unique_ptr<mongo::exec::agg::Stage> execAggStage) {
        return std::make_unique<NoOpHostExecAggStage>(std::move(execAggStage));
    }
};

class NoOpExtensionExecAggStage : public sdk::ExecAggStage {
public:
    NoOpExtensionExecAggStage() : sdk::ExecAggStage() {}

    ExtensionGetNextResult getNext() override {
        MONGO_UNIMPLEMENTED;
    }
    static inline std::unique_ptr<sdk::ExecAggStage> make() {
        return std::make_unique<NoOpExtensionExecAggStage>();
    }
};

TEST(HostExecAggStageTest, GetNextResult) {
    using ReturnStatus = exec::agg::GetNextResult::ReturnStatus;
    boost::intrusive_ptr<DocumentSourceMatch> matchDocSourceStage =
        DocumentSourceMatch::create(BSON("a" << 1), make_intrusive<ExpressionContextForTest>());

    auto mock =
        DocumentSourceMock::createForTest({DocumentSource::GetNextResult::makePauseExecution(),
                                           DocumentSource::GetNextResult::makePauseExecution(),
                                           Document{{"a", 1}},
                                           Document{{"a", 2}},
                                           Document{{"a", 2}}},
                                          make_intrusive<ExpressionContextForTest>());
    exec::agg::StagePtr matchExecAggStage = exec::agg::buildStage(matchDocSourceStage);
    exec::agg::StagePtr mockStage = exec::agg::buildStage(mock);

    matchExecAggStage->setSource(mockStage.get());

    std::unique_ptr<host::ExecAggStage> execAggStage = NoOpHostExecAggStage::make(
        std::unique_ptr<mongo::exec::agg::Stage>(matchExecAggStage.detach()));

    // Test ExecAggStage::getNext() which calls the stored exec agg stage's getNext().
    auto getNextResult = execAggStage->getNext();
    ASSERT_EQ(ReturnStatus::kPauseExecution, getNextResult.getStatus());

    // Test getNext() via ExecAggStageHandle.
    auto hostExecAggStage = new host_connector::HostExecAggStageAdapter(std::move(execAggStage));
    auto handle = host_connector::ExecAggStageHandle{hostExecAggStage};

    auto hostGetNextResult = handle.getNext();
    ASSERT_EQ(extension::GetNextCode::kPauseExecution, hostGetNextResult.code);
    ASSERT_EQ(boost::none, hostGetNextResult.res);

    hostGetNextResult = handle.getNext();
    ASSERT_EQ(extension::GetNextCode::kAdvanced, hostGetNextResult.code);
    ASSERT_BSONOBJ_EQ(BSON("a" << 1), hostGetNextResult.res.get());

    // Note that the match clause is "a": 1 so the documents where "a": 2 will be passed over.
    hostGetNextResult = handle.getNext();
    ASSERT_EQ(extension::GetNextCode::kEOF, hostGetNextResult.code);
    ASSERT_EQ(boost::none, hostGetNextResult.res);

    // Confirm the ownership of the result was correctly passed to the caller. To do that, create a
    // dummy host_connector::HostExecAggStageAdapter so the initial underlying
    // ::MongoExtensionExecAggStage gets deleted.
    exec::agg::StagePtr duplicateMatchExecAggStage = exec::agg::buildStage(
        DocumentSourceMatch::create(BSON("a" << 2), make_intrusive<ExpressionContextForTest>()));
    std::unique_ptr<host::ExecAggStage> duplicateExecAgg = NoOpHostExecAggStage::make(
        std::unique_ptr<mongo::exec::agg::Stage>(duplicateMatchExecAggStage.detach()));

    auto duplicateHostExecAggStage =
        new host_connector::HostExecAggStageAdapter(std::move(duplicateExecAgg));
    handle = host_connector::ExecAggStageHandle{duplicateHostExecAggStage};

    ASSERT_EQ(extension::GetNextCode::kEOF, hostGetNextResult.code);
    ASSERT_EQ(boost::none, hostGetNextResult.res);
}

TEST(HostExecAggStageTest, GetNextResultEdgeCaseEof) {
    using ReturnStatus = exec::agg::GetNextResult::ReturnStatus;
    boost::intrusive_ptr<DocumentSourceMatch> matchDocSourceStage =
        DocumentSourceMatch::create(BSON("a" << 1), make_intrusive<ExpressionContextForTest>());

    auto mock = DocumentSourceMock::createForTest({}, make_intrusive<ExpressionContextForTest>());
    exec::agg::StagePtr matchExecAggStage = exec::agg::buildStage(matchDocSourceStage);
    exec::agg::StagePtr mockStage = exec::agg::buildStage(mock);

    matchExecAggStage->setSource(mockStage.get());

    std::unique_ptr<host::ExecAggStage> execAggStage = NoOpHostExecAggStage::make(
        std::unique_ptr<mongo::exec::agg::Stage>(matchExecAggStage.detach()));

    // Test getNext() via ExecAggStageHandle.
    auto hostExecAggStage = new host_connector::HostExecAggStageAdapter(std::move(execAggStage));
    auto handle = host_connector::ExecAggStageHandle{hostExecAggStage};

    auto hostGetNextResult = handle.getNext();
    ASSERT_EQ(extension::GetNextCode::kEOF, hostGetNextResult.code);
    ASSERT_EQ(boost::none, hostGetNextResult.res);
}

DEATH_TEST_F(ExecAggStageTest, InvalidReturnStatusCode, "11019500") {
    using ReturnStatus = exec::agg::GetNextResult::ReturnStatus;
    // Need to set this metadata, so we don't hit the dassert in makeAdvancedControlDocument(...).
    MutableDocument doc(Document{BSON("a" << 1)});
    doc.metadata().setChangeStreamControlEvent();

    boost::intrusive_ptr<DocumentSourceMatch> matchDocSourceStage =
        DocumentSourceMatch::create(BSON("a" << 1), make_intrusive<ExpressionContextForTest>());

    auto mock = DocumentSourceMock::createForTest(
        {
            DocumentSource::GetNextResult::makeAdvancedControlDocument(doc.freeze()),
        },
        make_intrusive<ExpressionContextForTest>());
    exec::agg::StagePtr matchExecAggStage = exec::agg::buildStage(matchDocSourceStage);
    exec::agg::StagePtr mockStage = exec::agg::buildStage(mock);

    matchExecAggStage->setSource(mockStage.get());

    std::unique_ptr<host::ExecAggStage> execAggStage = NoOpHostExecAggStage::make(
        std::unique_ptr<mongo::exec::agg::Stage>(matchExecAggStage.detach()));

    auto hostExecAggStage = new host_connector::HostExecAggStageAdapter(std::move(execAggStage));
    auto handle = host_connector::ExecAggStageHandle{hostExecAggStage};

    // This getNext() call should hit the tassert because the C API doesn't have a
    // kAdvancedControlDocument value for GetNextCode.
    handle.getNext();
}

TEST(HostExecAggStageTest, IsHostAllocated) {
    boost::intrusive_ptr<DocumentSourceMatch> matchDocSourceStage =
        DocumentSourceMatch::create(BSON("a" << 1), make_intrusive<ExpressionContextForTest>());
    exec::agg::StagePtr matchExecAggStage = exec::agg::buildStage(matchDocSourceStage);
    auto hostExecAggStage = new host_connector::HostExecAggStageAdapter(NoOpHostExecAggStage::make(
        std::unique_ptr<mongo::exec::agg::Stage>(matchExecAggStage.detach())));
    auto handle = host_connector::ExecAggStageHandle{hostExecAggStage};

    ASSERT_TRUE(host_connector::HostExecAggStageAdapter::isHostAllocated(*handle.get()));
}

TEST(HostExecAggStageTest, IsNotHostAllocated) {
    auto noOpExtensionExecAggStage =
        new sdk::ExtensionExecAggStage(NoOpExtensionExecAggStage::make());
    auto handle = host_connector::ExecAggStageHandle{noOpExtensionExecAggStage};

    ASSERT_FALSE(host_connector::HostExecAggStageAdapter::isHostAllocated(*handle.get()));
}

}  // namespace

}  // namespace mongo::extension
