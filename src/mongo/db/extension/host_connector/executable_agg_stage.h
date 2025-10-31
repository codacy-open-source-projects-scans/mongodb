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
#pragma once

#include "mongo/db/extension/shared/get_next_result.h"
#include "mongo/db/extension/shared/handle/byte_buf_handle.h"
#include "mongo/db/extension/shared/handle/handle.h"
#include "mongo/util/modules.h"

namespace mongo::extension::host_connector {

/**
 * Takes a MongoExtensionGetNextResult C struct and sets the code and result field of the
 * ExtensionGetNextResult C++ struct accordingly. If the MongoExtensionGetNextResult struct has an
 * invalid code, asserts in that case.
 */
static ExtensionGetNextResult convertCRepresentationToGetNextResult(
    ::MongoExtensionGetNextResult* const apiResult) {
    switch (apiResult->code) {
        case ::MongoExtensionGetNextResultCode::kAdvanced: {
            // Take ownership of the returned buffer so that it gets cleaned up, then retrieve an
            // owned BSONObj to return to the host
            ExtensionByteBufHandle ownedBuf{apiResult->result};
            BSONObj objResult = bsonObjFromByteView(ownedBuf.getByteView()).getOwned();
            return ExtensionGetNextResult{.code = GetNextCode::kAdvanced,
                                          .res = boost::make_optional(objResult)};
        }
        case ::MongoExtensionGetNextResultCode::kPauseExecution:
            return ExtensionGetNextResult{.code = GetNextCode::kPauseExecution, .res = boost::none};
        case ::MongoExtensionGetNextResultCode::kEOF: {
            return ExtensionGetNextResult{.code = GetNextCode::kEOF, .res = boost::none};
        }
        default:
            tasserted(
                10956803,
                (str::stream() << "Invalid MongoExtensionGetNextResultCode: " << apiResult->code));
    }
}

/**
 * ExecAggStageHandle is a wrapper around a MongoExtensionExecAggStage.
 */
class ExecAggStageHandle : public OwnedHandle<::MongoExtensionExecAggStage> {
public:
    ExecAggStageHandle(absl::Nonnull<::MongoExtensionExecAggStage*> execAggStage)
        : OwnedHandle<::MongoExtensionExecAggStage>(execAggStage) {
        _assertValidVTable();
    }

    ExtensionGetNextResult getNext();

protected:
    void _assertVTableConstraints(const VTable_t& vtable) const override {
        tassert(10956800, "ExecAggStage 'get_next' is null", vtable.get_next != nullptr);
    }
};

}  // namespace mongo::extension::host_connector
