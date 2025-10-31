/**
 *    Copyright (C) 2019-present MongoDB, Inc.
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

#include <boost/move/utility_core.hpp>
#include <boost/optional/optional.hpp>
#include <fmt/format.h>
// IWYU pragma: no_include "ext/alloc_traits.h"
#include "mongo/base/status_with.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/bsonelement.h"
#include "mongo/bson/bsonmisc.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/timestamp.h"
#include "mongo/bson/util/builder.h"
#include "mongo/db/client.h"
#include "mongo/db/collection_crud/collection_write_path.h"
#include "mongo/db/index/index_access_method.h"
#include "mongo/db/local_catalog/catalog_raii.h"
#include "mongo/db/local_catalog/catalog_test_fixture.h"
#include "mongo/db/local_catalog/collection.h"
#include "mongo/db/local_catalog/collection_options.h"
#include "mongo/db/local_catalog/index_catalog.h"
#include "mongo/db/local_catalog/index_catalog_entry.h"
#include "mongo/db/local_catalog/lock_manager/lock_manager_defs.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/repl/oplog.h"
#include "mongo/db/repl/optime.h"
#include "mongo/db/repl/storage_interface.h"
#include "mongo/db/service_context.h"
#include "mongo/db/storage/key_string/key_string.h"
#include "mongo/db/storage/record_store.h"
#include "mongo/db/storage/recovery_unit.h"
#include "mongo/db/storage/sorted_data_interface.h"
#include "mongo/db/storage/sorted_data_interface_test_assert.h"
#include "mongo/db/storage/write_unit_of_work.h"
#include "mongo/db/validate/collection_validation.h"
#include "mongo/db/validate/validate_results.h"
#include "mongo/unittest/unittest.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/bufreader.h"
#include "mongo/util/fail_point.h"
#include "mongo/util/shared_buffer.h"
#include "mongo/util/str.h"
#include "mongo/util/time_support.h"

#include <cstdint>
#include <initializer_list>
#include <limits>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

namespace mongo {
namespace {

const NamespaceString kNss = NamespaceString::createNamespaceString_forTest("test.t");

class CollectionValidationTest : public CatalogTestFixture {
protected:
    CollectionValidationTest(Options options = {}) : CatalogTestFixture(std::move(options)) {}

private:
    void setUp() override {
        CatalogTestFixture::setUp();

        // Create collection kNss for unit tests to use. It will possess a default _id index.
        const CollectionOptions defaultCollectionOptions;
        ASSERT_OK(storageInterface()->createCollection(
            operationContext(), kNss, defaultCollectionOptions));
    };
};

// Calling verify() is not possible on an in-memory instance.
class CollectionValidationDiskTest : public CollectionValidationTest {
protected:
    CollectionValidationDiskTest() : CollectionValidationTest(Options{}.inMemory(false)) {}
};

struct ForegroundValidateTestResults {
    bool valid{true};
    int numRecords{0};
    int numInvalidDocuments{0};
    int numNonCompliantDocuments{0};
    int numErrors{0};
    int numWarnings{0};
    auto operator<=>(const ForegroundValidateTestResults&) const = default;
};

inline std::string stringify_forTest(const ForegroundValidateTestResults& fgRes) {
    return fmt::format(
        "{{valid={}, numRecords={}, numInvalidDocuments={}, numErrors={}, numWarnings={}}}",
        fgRes.valid,
        fgRes.numRecords,
        fgRes.numInvalidDocuments,
        fgRes.numErrors,
        fgRes.numWarnings);
}

/**
 * Calls validate on collection nss with both kValidateFull and kValidateNormal validation levels
 * and verifies the results.
 *
 * Returns the list of validation results.
 */
std::vector<ValidateResults> foregroundValidate(
    const NamespaceString& nss,
    OperationContext* opCtx,
    const ForegroundValidateTestResults& expected,
    std::initializer_list<CollectionValidation::ValidateMode> modes =
        {CollectionValidation::ValidateMode::kForeground,
         CollectionValidation::ValidateMode::kForegroundFull},
    CollectionValidation::RepairMode repairMode = CollectionValidation::RepairMode::kNone) {

    std::vector<ValidateResults> results;

    for (auto mode : modes) {
        ValidateResults validateResults;
        ASSERT_OK(CollectionValidation::validate(
            opCtx,
            nss,
            CollectionValidation::ValidationOptions{mode,
                                                    repairMode,
                                                    /*logDiagnostics=*/false},
            &validateResults));
        BSONObjBuilder validateResultsBuilder;
        validateResults.appendToResultObj(&validateResultsBuilder, true /* debugging */);
        auto validateResultsObj = validateResultsBuilder.obj();

        // The total number of errors is: those in the top-level results plus the sum of
        // all index-specific errors.
        const int observedNumErrors = validateResults.getErrors().size() +
            std::accumulate(validateResults.getIndexResultsMap().begin(),
                            validateResults.getIndexResultsMap().end(),
                            0,
                            [](size_t current, const auto& ivr) {
                                return current + ivr.second.getErrors().size();
                            });

        const ForegroundValidateTestResults actual{
            .valid = validateResults.isValid(),
            .numRecords = validateResultsObj.getIntField("nrecords"),
            .numInvalidDocuments = validateResultsObj.getIntField("nInvalidDocuments"),
            .numErrors = observedNumErrors,
            .numWarnings = static_cast<int>(validateResults.getWarnings().size())};

        ASSERT_EQ(expected, actual) << validateResultsObj;
        results.push_back(std::move(validateResults));
    }
    return results;
}

/**
 * Inserts a range of documents into the nss collection and then returns that count. The range is
 * defined by [startIDNum, startIDNum+numDocs), not inclusive of (startIDNum+numDocs), using the
 * numbers as values for '_id' of the document being inserted followed by numFields fields.
 */
int insertDataRangeForNumFields(const NamespaceString& nss,
                                OperationContext* opCtx,
                                const int startIDNum,
                                const int numDocs,
                                const int numFields) {
    const AutoGetCollection coll(opCtx, nss, MODE_IX);
    std::vector<InsertStatement> inserts;
    for (int i = 0; i < numDocs; ++i) {
        BSONObjBuilder bsonBuilder;
        bsonBuilder << "_id" << i + startIDNum;
        for (int c = 1; c <= numFields; ++c) {
            bsonBuilder << "a" + std::to_string(c) << i + (i * numFields + startIDNum) + c;
        }
        const auto obj = bsonBuilder.obj();
        inserts.push_back(InsertStatement(obj));
    }

    {
        WriteUnitOfWork wuow(opCtx);
        ASSERT_OK(collection_internal::insertDocuments(
            opCtx, *coll, inserts.begin(), inserts.end(), nullptr, false));
        wuow.commit();
    }
    return numDocs;
}

/**
 * Inserts a range of documents into the kNss collection and then returns that count. The range is
 * defined by [startIDNum, endIDNum), not inclusive of endIDNum, using the numbers as values for
 * '_id' of the document being inserted.
 */
int insertDataRange(OperationContext* opCtx, const int startIDNum, const int endIDNum) {
    invariant(startIDNum < endIDNum,
              str::stream() << "attempted to insert invalid data range from " << startIDNum
                            << " to " << endIDNum);

    return insertDataRangeForNumFields(kNss, opCtx, startIDNum, endIDNum - startIDNum, 0);
}

int setUpDataOfGivenSize(OperationContext* opCtx,
                         int targetBsonSize,
                         const NamespaceString& nss = kNss) {
    ASSERT_TRUE(opCtx);
    AutoGetCollection coll(opCtx, nss, MODE_IX);

    // Build a temporary BSON object to determine the overhead. This overhead will need to be
    // subtracted from the test objects to set their sizes close to limits.
    const int overhead = std::invoke([] {
        BSONObjBuilder builder;
        std::string testStr("test");
        builder.append("_id", testStr);
        return builder.obj().objsize() - testStr.size();
    });

    BSONObjBuilder builder;
    builder.append("_id", std::string(targetBsonSize - overhead, 'a'));
    BSONObj oversizeObj = builder.obj();
    {
        WriteUnitOfWork wuow(opCtx);
        ASSERT_OK(collection_internal::insertDocument(
            opCtx, *coll, InsertStatement(oversizeObj), nullptr))
            << "Failed to insert object of size " << targetBsonSize;
        wuow.commit();
    }
    return 1;
}

/**
 * Inserts a single invalid document into the kNss collection and then returns that count.
 */
int setUpInvalidData(OperationContext* opCtx) {
    AutoGetCollection coll(opCtx, kNss, MODE_IX);
    RecordStore* rs = coll->getRecordStore();

    {
        WriteUnitOfWork wuow(opCtx);
        auto invalidBson = "\0\0\0\0\0"_sd;
        ASSERT_OK(rs->insertRecord(opCtx,
                                   *shard_role_details::getRecoveryUnit(opCtx),
                                   invalidBson.data(),
                                   invalidBson.size(),
                                   Timestamp::min())
                      .getStatus());
        wuow.commit();
    }

    return 1;
}

/**
 * Convenience function to convert ValidateResults to a BSON object.
 */
BSONObj resultToBSON(const ValidateResults& vr) {
    BSONObjBuilder builder;
    vr.appendToResultObj(&builder, true /* debugging */);
    return builder.obj();
}


// Verify that calling validate() on an empty collection with different validation levels returns an
// OK status.
TEST_F(CollectionValidationTest, ValidateEmpty) {
    foregroundValidate(kNss,
                       operationContext(),
                       {.valid = true,
                        .numRecords = 0,
                        .numInvalidDocuments = 0,
                        .numErrors = 0,
                        .numWarnings = 0});
}

// Verify calling validate() on a nonempty collection with different validation levels.
TEST_F(CollectionValidationTest, Validate) {
    auto opCtx = operationContext();
    foregroundValidate(kNss,
                       opCtx,
                       {.valid = true,
                        .numRecords = insertDataRange(opCtx, 0, 5),
                        .numInvalidDocuments = 0,
                        .numErrors = 0});
}

// Verify calling validate() on a collection with an invalid document.
TEST_F(CollectionValidationTest, ValidateError) {
    auto opCtx = operationContext();
    foregroundValidate(kNss,
                       opCtx,
                       {.valid = false,
                        .numRecords = setUpInvalidData(opCtx),
                        .numInvalidDocuments = 1,
                        .numErrors = 1});
}

// Verify calling validate() with enforceFastCount=true.
TEST_F(CollectionValidationTest, ValidateEnforceFastCount) {
    auto opCtx = operationContext();
    foregroundValidate(kNss,
                       opCtx,
                       {.valid = true,
                        .numRecords = insertDataRange(opCtx, 0, 5),
                        .numInvalidDocuments = 0,
                        .numErrors = 0},
                       {CollectionValidation::ValidateMode::kForegroundFullEnforceFastCount});
}

TEST_F(CollectionValidationTest, ValidateCollectionDocumentSizeUserLimit) {
    auto opCtx = operationContext();
    foregroundValidate(kNss,
                       opCtx,
                       {.valid = true,
                        .numRecords = setUpDataOfGivenSize(opCtx, BSONObjMaxUserSize),
                        .numInvalidDocuments = 0,
                        .numErrors = 0,
                        .numWarnings = 0},
                       {CollectionValidation::ValidateMode::kForegroundCheckBSON});
}

TEST_F(CollectionValidationTest, ValidateCollectionDocumentSizeOverUserLimit) {
    auto opCtx = operationContext();
    foregroundValidate(kNss,
                       opCtx,
                       {.valid = false,
                        .numRecords = setUpDataOfGivenSize(opCtx, BSONObjMaxUserSize + 1),
                        .numInvalidDocuments = 1,
                        .numErrors = 1,
                        .numWarnings = 0},
                       {CollectionValidation::ValidateMode::kForegroundCheckBSON});
}

TEST_F(CollectionValidationTest, ValidateCollectionDocumentSizeInternalLimit) {
    auto opCtx = operationContext();
    foregroundValidate(kNss,
                       opCtx,
                       {.valid = false,
                        .numRecords = setUpDataOfGivenSize(opCtx, BSONObjMaxInternalSize),
                        .numInvalidDocuments = 1,
                        .numErrors = 1,
                        .numWarnings = 0},
                       {CollectionValidation::ValidateMode::kForegroundCheckBSON});
}

TEST_F(CollectionValidationTest, ValidateCollectionDocumentSizeOverInternalLimit) {
    auto opCtx = operationContext();
    foregroundValidate(kNss,
                       opCtx,
                       {.valid = false,
                        .numRecords = setUpDataOfGivenSize(opCtx, BSONObjMaxInternalSize + 1),
                        .numInvalidDocuments = 1,
                        .numErrors = 1,
                        .numWarnings = 0},
                       {CollectionValidation::ValidateMode::kForegroundCheckBSON});
}

TEST_F(CollectionValidationTest, ValidateCollectionDocumentMixedSizes) {
    auto opCtx = operationContext();
    setUpDataOfGivenSize(opCtx, BSONObjMaxInternalSize);
    setUpDataOfGivenSize(opCtx, BSONObjMaxInternalSize + 1);
    setUpDataOfGivenSize(opCtx, BSONObjMaxUserSize);
    setUpDataOfGivenSize(opCtx, BSONObjMaxUserSize + 1);
    foregroundValidate(kNss,
                       opCtx,
                       {.valid = false,
                        .numRecords = 4,
                        .numInvalidDocuments = 3,
                        .numErrors = 1,
                        .numWarnings = 0},
                       {CollectionValidation::ValidateMode::kForegroundCheckBSON});
}

TEST_F(CollectionValidationDiskTest, ValidateIndexDetailResultsSurfaceVerifyErrors) {
    FailPointEnableBlock fp{"WTValidateIndexStructuralDamage"};
    auto opCtx = operationContext();
    insertDataRange(opCtx, 0, 5);  // initialize collection
    foregroundValidate(
        kNss,
        opCtx,
        {.valid = false,
         .numRecords = std::numeric_limits<int32_t>::min(),           // uninitialized
         .numInvalidDocuments = std::numeric_limits<int32_t>::min(),  // uninitialized
         .numErrors = 1,
         .numWarnings = 1},
        {CollectionValidation::ValidateMode::kForegroundFull});
}

/**
 * Waits for a parallel running collection validation operation to start and then hang at a
 * failpoint.
 *
 * A failpoint in the validate() code should have been set prior to calling this function.
 */
void waitUntilValidateFailpointHasBeenReached() {
    while (!CollectionValidation::getIsValidationPausedForTest()) {
        sleepmillis(100);  // a fairly arbitrary sleep period.
    }
    ASSERT(CollectionValidation::getIsValidationPausedForTest());
}

/**
 * Generates a KeyString suitable for positioning a cursor at the beginning of an index.
 */
key_string::Value makeFirstKeyString(const SortedDataInterface& sortedDataInterface) {
    key_string::Builder firstKeyStringBuilder(sortedDataInterface.getKeyStringVersion(),
                                              BSONObj(),
                                              sortedDataInterface.getOrdering(),
                                              key_string::Discriminator::kExclusiveBefore);
    return firstKeyStringBuilder.getValueCopy();
}

/**
 * Extracts KeyString without RecordId.
 */
key_string::Value makeKeyStringWithoutRecordId(const key_string::View& keyStringWithRecordId,
                                               key_string::Version version) {
    BufBuilder bufBuilder;
    keyStringWithRecordId.serializeWithoutRecordId(bufBuilder);
    auto builderSize = bufBuilder.len();

    auto buffer = bufBuilder.release();

    BufReader bufReader(buffer.get(), builderSize);
    return key_string::Value::deserialize(bufReader, version, boost::none /* ridFormat */);
}

// Verify calling validate() on a collection with old (pre-4.2) keys in a WT unique index.
TEST_F(CollectionValidationTest, ValidateOldUniqueIndexKeyWarning) {
    auto opCtx = operationContext();

    {
        FailPointEnableBlock createOldFormatIndex("WTIndexCreateUniqueIndexesInOldFormat");

        // Durable catalog expects metadata updates to be timestamped but this is
        // not necessary in our case - we just want to check the contents of the index table.
        // The alternative here would be to provide a commit timestamp with a TimestamptBlock.
        repl::UnreplicatedWritesBlock uwb(opCtx);
        auto uniqueIndexSpec = BSON("v" << 2 << "name"
                                        << "a_1"
                                        << "key" << BSON("a" << 1) << "unique" << true);
        ASSERT_OK(
            storageInterface()->createIndexesOnEmptyCollection(opCtx, kNss, {uniqueIndexSpec}));
    }

    // Insert single document with the default (new) index key that includes a record id.
    ASSERT_OK(storageInterface()->insertDocument(opCtx,
                                                 kNss,
                                                 {BSON("_id" << 1 << "a" << 1), Timestamp()},
                                                 repl::OpTime::kUninitializedTerm));

    // Validate the collection here as a sanity check before we modify the index contents in-place.
    foregroundValidate(kNss,
                       opCtx,
                       {.valid = true,
                        .numRecords = 1,
                        .numInvalidDocuments = 0,
                        .numErrors = 0,
                        .numWarnings = 0});

    // Update existing entry in index to pre-4.2 format without record id in key string.
    {
        AutoGetCollection autoColl(opCtx, kNss, MODE_IX);

        auto indexCatalog = autoColl->getIndexCatalog();
        auto descriptor = indexCatalog->findIndexByName(opCtx, "a_1");
        ASSERT(descriptor) << "Cannot find a_1 in index catalog";
        auto entry = indexCatalog->getEntry(descriptor);
        ASSERT(entry) << "Cannot look up index catalog entry for index a_1";

        auto& ru = *shard_role_details::getRecoveryUnit(opCtx);

        auto sortedDataInterface = entry->accessMethod()->asSortedData()->getSortedDataInterface();
        ASSERT_FALSE(sortedDataInterface->isEmpty(opCtx, ru)) << "index a_1 should not be empty";

        // Check key in index for only document.
        auto first = makeFirstKeyString(*sortedDataInterface);
        auto firstKeyString = first.getView();
        key_string::Value keyStringWithRecordId;
        {
            auto cursor = sortedDataInterface->newCursor(opCtx, ru);
            auto indexEntry = cursor->seekForKeyString(ru, firstKeyString);
            ASSERT(indexEntry);
            ASSERT(cursor->isRecordIdAtEndOfKeyString());
            keyStringWithRecordId = indexEntry->keyString;
            ASSERT_FALSE(cursor->nextKeyString(ru));
        }

        // Replace key with old format (without record id).
        {
            WriteUnitOfWork wuow(opCtx);
            bool dupsAllowed = false;
            sortedDataInterface->unindex(opCtx, ru, keyStringWithRecordId, dupsAllowed);
            FailPointEnableBlock insertOldFormatKeys("WTIndexInsertUniqueKeysInOldFormat");
            ASSERT_SDI_INSERT_OK(
                sortedDataInterface->insert(opCtx, ru, keyStringWithRecordId, dupsAllowed));
            wuow.commit();
        }

        // Confirm that key in index is in old format.
        {
            auto cursor = sortedDataInterface->newCursor(opCtx, ru);
            auto indexEntry = cursor->seekForKeyString(ru, firstKeyString);
            ASSERT(indexEntry);
            ASSERT_FALSE(cursor->isRecordIdAtEndOfKeyString());
            ASSERT_EQ(indexEntry->keyString.compareWithoutRecordIdLong(keyStringWithRecordId), 0);
            ASSERT_FALSE(cursor->nextKeyString(ru));
        }
    }

    const auto results = foregroundValidate(kNss,
                                            opCtx,
                                            {.valid = true,
                                             .numRecords = 1,
                                             .numInvalidDocuments = 0,
                                             .numErrors = 0,
                                             .numWarnings = 1});
    ASSERT_EQ(results.size(), 2);

    for (const auto& validateResults : results) {
        const auto obj = resultToBSON(validateResults);
        ASSERT(validateResults.isValid()) << obj;
        auto isOldFormat = [](const auto& warn) {
            return warn.find("Unique index a_1 has one or more keys in the old format") !=
                std::string::npos;
        };
        ASSERT(std::any_of(validateResults.getWarnings().begin(),
                           validateResults.getWarnings().end(),
                           isOldFormat))
            << obj;
    }
}

TEST_F(CollectionValidationTest, HashPrefixesEmptyString) {
    ASSERT_THROWS_CODE(CollectionValidation::validateHashes({""}, /*equalLength=*/true),
                       DBException,
                       ErrorCodes::InvalidOptions);
    ASSERT_THROWS_CODE(CollectionValidation::validateHashes({""}, /*equalLength=*/false),
                       DBException,
                       ErrorCodes::InvalidOptions);
}

TEST_F(CollectionValidationTest, HashPrefixesTooLong) {
    constexpr int kHashStringMaxLen = 64;
    ASSERT_DOES_NOT_THROW(CollectionValidation::validateHashes(
        {std::string(kHashStringMaxLen, 'A')}, /*equalLength=*/true));

    ASSERT_THROWS_CODE(CollectionValidation::validateHashes(
                           {std::string(kHashStringMaxLen + 1, 'A')}, /*equalLength=*/true),
                       DBException,
                       ErrorCodes::InvalidOptions);
    ASSERT_THROWS_CODE(CollectionValidation::validateHashes(
                           {std::string(kHashStringMaxLen + 1, 'A')}, /*equalLength=*/false),
                       DBException,
                       ErrorCodes::InvalidOptions);
}

TEST_F(CollectionValidationTest, HashPrefixesDifferentLengths) {
    ASSERT_DOES_NOT_THROW(
        CollectionValidation::validateHashes({"AAA", "BBBB"}, /*equalLength=*/false));

    ASSERT_THROWS_CODE(CollectionValidation::validateHashes({"AAA", "BBBB"}, /*equalLength=*/true),
                       DBException,
                       ErrorCodes::InvalidOptions);
}

TEST_F(CollectionValidationTest, HashPrefixesHexString) {
    ASSERT_THROWS_CODE(CollectionValidation::validateHashes({"NOTHEX"}, /*equalLength=*/true),
                       DBException,
                       ErrorCodes::InvalidOptions);
    ASSERT_THROWS_CODE(CollectionValidation::validateHashes({"NOTHEX"}, /*equalLength=*/false),
                       DBException,
                       ErrorCodes::InvalidOptions);
}

TEST_F(CollectionValidationTest, HashPrefixesDuplicates) {
    ASSERT_THROWS_CODE(CollectionValidation::validateHashes({"ABC", "ABC"}, /*equalLength=*/true),
                       DBException,
                       ErrorCodes::InvalidOptions);
    ASSERT_THROWS_CODE(
        CollectionValidation::validateHashes({"ABC", "ABCD", "A"}, /*equalLength=*/false),
        DBException,
        ErrorCodes::InvalidOptions);
}

TEST_F(CollectionValidationTest, HashPrefixesCases) {
    constexpr int kHashStringMaxLen = 64;
    ASSERT_DOES_NOT_THROW(
        CollectionValidation::validateHashes({"AAA1", "BBB1", "CCC1"}, /*equalLength=*/true));
    ASSERT_DOES_NOT_THROW(CollectionValidation::validateHashes(
        {std::string(kHashStringMaxLen, 'A')}, /*equalLength=*/true));

    ASSERT_THROWS_CODE(CollectionValidation::validateHashes({"a"}, /*equalLength=*/true),
                       DBException,
                       ErrorCodes::InvalidOptions);
    ASSERT_THROWS_CODE(CollectionValidation::validateHashes({"AAA", "BBBB"}, /*equalLength=*/true),
                       DBException,
                       ErrorCodes::InvalidOptions);
    ASSERT_THROWS_CODE(CollectionValidation::validateHashes({"nothex"}, /*equalLength=*/true),
                       DBException,
                       ErrorCodes::InvalidOptions);
    ASSERT_THROWS_CODE(CollectionValidation::validateHashes({"AAA", "AAA"}, /*equalLength=*/true),
                       DBException,
                       ErrorCodes::InvalidOptions);
    ASSERT_THROWS_CODE(
        CollectionValidation::validateHashes({"abcd", "a", "ABCDEF"}, /*equalLength=*/true),
        DBException,
        ErrorCodes::InvalidOptions);
}

}  // namespace
}  // namespace mongo
