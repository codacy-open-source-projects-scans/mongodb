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

#pragma once

#include "mongo/db/query/query_planner_params.h"
#include "mongo/db/query/query_solution.h"

namespace mongo {

/**
 * Return whether or not any component of the path 'path' is multikey given an index key pattern
 * and multikeypaths. If no multikey metdata is available for the index, and the index is marked
 * multikey, conservatively assumes that a component of 'path' _is_ multikey. The 'isMultikey'
 * property of an index is false for indexes that definitely have no multikey paths.
 */
bool isAnyComponentOfPathMultikey(const BSONObj& indexKeyPattern,
                                  bool isMultikey,
                                  const MultikeyPaths& indexMultikeyInfo,
                                  StringData path);

/**
 * If possible, turn the provided QuerySolution into a QuerySolution that uses a DistinctNode
 * to provide results for the distinct command.
 *
 * When 'strictDistinctOnly' is false, any resulting QuerySolution will limit the number of
 * documents that need to be examined to compute the results of a distinct command, but it may not
 * guarantee that there are no duplicate values for the distinct field.
 *
 * If the provided solution could be mutated successfully, returns true, otherwise returns
 * false. This conversion is known as the 'distinct hack'.
 */
bool turnIxscanIntoDistinctIxscan(const CanonicalQuery& canonicalQuery,
                                  QuerySolution* soln,
                                  const std::string& field,
                                  bool strictDistinctOnly,
                                  bool flipDistinctScanDirection = false);

/**
 * If the canonical query doesn't have a filter and a sort, the query planner won't try to build an
 * index scan, so we will try to create a DISTINCT_SCAN manually.
 *
 * Othewise, if the distinct multiplanner is disabled, we will return the first query solution that
 * can be transformed to an DISTINCT_SCAN from the candidates returned by the query planner.
 */
std::unique_ptr<QuerySolution> createDistinctScanSolution(const CanonicalQuery& canonicalQuery,
                                                          const QueryPlannerParams& plannerParams,
                                                          bool isDistinctMultiplanningEnabled,
                                                          bool flipDistinctScanDirection);

}  // namespace mongo