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

#include "mongo/db/extension/sdk/host_services.h"

#include "mongo/db/extension/host_connector/host_services_adapter.h"
#include "mongo/unittest/death_test.h"
#include "mongo/unittest/unittest.h"

#include <string>

namespace mongo::extension {
namespace {

class HostServicesTest : public unittest::Test {
public:
    void setUp() override {
        sdk::HostServicesHandle::setHostServices(host_connector::HostServicesAdapter::get());
    }
};

/**
 * Tests that the ExtensionLog created by HostServicesHandle::createExtensionLogMessage can be
 * round-tripped through MongoExtensionByteView serialization and deserialization.
 */
TEST_F(HostServicesTest, ExtensionLogIDLRoundTrip) {
    std::string logMessage = "Test log message";
    std::int32_t logCode = 12345;
    MongoExtensionLogSeverityEnum logSeverity = MongoExtensionLogSeverityEnum::kInfo;

    BSONObj structuredLog =
        sdk::HostServicesHandle::createExtensionLogMessage(logMessage, logCode, logSeverity);
    ::MongoExtensionByteView byteView = objAsByteView(structuredLog);

    ASSERT(byteView.data != nullptr);
    ASSERT(byteView.len > 0);

    auto bsonObj = bsonObjFromByteView(byteView);
    auto log = MongoExtensionLog::parse(bsonObj);

    ASSERT_EQUALS(log.getMessage(), logMessage);
    ASSERT_EQUALS(log.getCode(), logCode);
    ASSERT_EQUALS(log.getSeverity(), logSeverity);
}

TEST_F(HostServicesTest, ExtensionDebugLogIDLRoundTrip) {
    std::string logMessage = "Test debug log message";
    std::int32_t logCode = 12345;
    std::int32_t logLevel = 1;

    BSONObj structuredDebugLog =
        sdk::HostServicesHandle::createExtensionDebugLogMessage(logMessage, logCode, logLevel);
    ::MongoExtensionByteView byteView = objAsByteView(structuredDebugLog);

    ASSERT(byteView.data != nullptr);
    ASSERT(byteView.len > 0);

    auto bsonObj = bsonObjFromByteView(byteView);
    auto debugLog = MongoExtensionDebugLog::parse(bsonObj);

    ASSERT_EQUALS(debugLog.getMessage(), logMessage);
    ASSERT_EQUALS(debugLog.getCode(), logCode);
    ASSERT_EQUALS(debugLog.getLevel(), logLevel);
}

TEST_F(HostServicesTest, userAsserted) {
    auto errmsg = "an error";
    int errorCode = 11111;
    BSONObj errInfo = BSON("message" << errmsg << "errorCode" << errorCode);
    ::MongoExtensionByteView errInfoByteView = objAsByteView(errInfo);

    StatusHandle status(sdk::HostServicesHandle::getHostServices()->userAsserted(errInfoByteView));

    ASSERT_EQ(status.getCode(), errorCode);
    // Reason is not populated on the status for re-throwable exceptions.
    ASSERT_EQ(status.getReason(), "");
}

DEATH_TEST_REGEX_F(HostServicesTest, tripwireAsserted, "22222") {
    auto errmsg = "fatal error";
    int errorCode = 22222;
    BSONObj errInfo = BSON("message" << errmsg << "errorCode" << errorCode);
    ::MongoExtensionByteView errInfoByteView = objAsByteView(errInfo);

    [[maybe_unused]] auto status =
        sdk::HostServicesHandle::getHostServices()->tripwireAsserted(errInfoByteView);
}
}  // namespace
}  // namespace mongo::extension
