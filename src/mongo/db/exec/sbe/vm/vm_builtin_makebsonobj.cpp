/**
 *    Copyright (C) 2024-present MongoDB, Inc.
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

// NO OTHER HEADERS AFTER THIS LINE
#define MONGO_SBE_VM_MAKEOBJ_H_WHITELIST
#include "mongo/db/exec/sbe/vm/vm_makeobj.h"

namespace mongo::sbe::vm {
FastTuple<bool, value::TypeTags, value::Value> ByteCode::builtinMakeBsonObj(
    ArityType arity, const CodeFragment* code) {
    tassert(6897002,
            str::stream() << "Unsupported number of args passed to makeBsonObj(): " << arity,
            arity >= 2);

    const int argsStackOff = 2;
    const uint32_t numArgs = arity - 2;
    const auto impl = MakeObjImpl{*this, argsStackOff, numArgs, code};

    return impl.makeObj<BsonObjWriter, BsonArrWriter>();
}
}  // namespace mongo::sbe::vm