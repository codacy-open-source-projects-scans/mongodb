/**
 *    Copyright (C) 2022-present MongoDB, Inc.
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


#include "mongo/db/global_catalog/router_role_api/router_role.h"

#include "mongo/base/error_codes.h"
#include "mongo/db/global_catalog/chunk_manager.h"
#include "mongo/db/global_catalog/router_role_api/cluster_commands_helpers.h"
#include "mongo/db/sharding_environment/grid.h"
#include "mongo/db/sharding_environment/mongod_and_mongos_server_parameters_gen.h"
#include "mongo/db/topology/sharding_state.h"
#include "mongo/db/versioning_protocol/shard_version.h"
#include "mongo/db/versioning_protocol/stale_exception.h"
#include "mongo/logv2/log.h"
#include "mongo/s/transaction_participant_failed_unyield_exception.h"
#include "mongo/s/transaction_router.h"
#include "mongo/util/str.h"

#include <utility>

#include <boost/move/utility_core.hpp>

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kSharding

namespace mongo {
namespace sharding {
namespace router {

RouterBase::RouterBase(CatalogCache* catalogCache) : _catalogCache(catalogCache) {}

void RouterBase::_initTxnRouterIfNeeded(OperationContext* opCtx) {
    bool activeTxnParticipantAddParticipants =
        opCtx->isActiveTransactionParticipant() && opCtx->inMultiDocumentTransaction();

    auto txnRouter = TransactionRouter::get(opCtx);
    if (txnRouter && activeTxnParticipantAddParticipants) {
        auto opCtxTxnNum = opCtx->getTxnNumber();
        invariant(opCtxTxnNum);
        txnRouter.beginOrContinueTxn(
            opCtx, *opCtxTxnNum, TransactionRouter::TransactionActions::kStartOrContinue);
    }
}

DBPrimaryRouter::DBPrimaryRouter(ServiceContext* service, const DatabaseName& db)
    : RouterBase(Grid::get(service)->catalogCache()), _dbName(db) {}

void DBPrimaryRouter::appendDDLRoutingTokenToCommand(const DatabaseType& dbt,
                                                     BSONObjBuilder* builder) {
    const auto& dbVersion = dbt.getVersion();
    if (!dbVersion.isFixed()) {
        BSONObjBuilder dbvBuilder(builder->subobjStart(DatabaseVersion::kDatabaseVersionField));
        dbVersion.serialize(&dbvBuilder);
    }
}

void DBPrimaryRouter::appendCRUDUnshardedRoutingTokenToCommand(const ShardId& shardId,
                                                               const DatabaseVersion& dbVersion,
                                                               BSONObjBuilder* builder) {
    if (!dbVersion.isFixed()) {
        BSONObjBuilder dbvBuilder(builder->subobjStart(DatabaseVersion::kDatabaseVersionField));
        dbVersion.serialize(&dbvBuilder);
    }
    appendShardVersion(*builder, ShardVersion::UNSHARDED());
}

CachedDatabaseInfo DBPrimaryRouter::_getRoutingInfo(OperationContext* opCtx) const {
    return uassertStatusOK(_catalogCache->getDatabase(opCtx, _dbName));
}

void DBPrimaryRouter::_onException(OperationContext* opCtx, RoutingRetryInfo* retryInfo, Status s) {
    if (s == ErrorCodes::StaleDbVersion) {
        auto si = s.extraInfo<StaleDbRoutingVersion>();
        tassert(6375900, "StaleDbVersion must have extraInfo", si);
        tassert(6375901,
                str::stream() << "StaleDbVersion on unexpected database. Expected "
                              << _dbName.toStringForErrorMsg() << ", received "
                              << si->getDb().toStringForErrorMsg(),
                si->getDb() == _dbName);

        _catalogCache->onStaleDatabaseVersion(si->getDb(), si->getVersionWanted());
    } else {
        uassertStatusOK(s);
    }

    // It is not safe to retry stale errors if running in a transaction.
    if (TransactionRouter::get(opCtx)) {
        uassertStatusOK(s);
    }

    int maxNumStaleVersionRetries = gMaxNumStaleVersionRetries.load();
    if (++retryInfo->numAttempts > maxNumStaleVersionRetries) {
        uassertStatusOKWithContext(s,
                                   str::stream()
                                       << "Exceeded maximum number of " << maxNumStaleVersionRetries
                                       << " retries attempting \'" << retryInfo->comment << "\'");
    } else {
        LOGV2_DEBUG(6375902,
                    3,
                    "Retrying database primary routing operation",
                    "attempt"_attr = retryInfo->numAttempts,
                    "comment"_attr = retryInfo->comment,
                    "status"_attr = s);
    }
}

CollectionRouterCommon::CollectionRouterCommon(
    CatalogCache* catalogCache, const std::vector<NamespaceString>& targetedNamespaces)
    : RouterBase(catalogCache), _targetedNamespaces(targetedNamespaces) {}

void CollectionRouterCommon::_onException(OperationContext* opCtx,
                                          RoutingRetryInfo* retryInfo,
                                          Status s) {
    const auto isNssInvolvedInRouting = [&](const NamespaceString& nss) {
        if (nss.isTimeseriesBucketsCollection() &&
            std::find(_targetedNamespaces.begin(),
                      _targetedNamespaces.end(),
                      nss.getTimeseriesViewNamespace()) != _targetedNamespaces.end()) {
            return true;
        }

        return std::find(_targetedNamespaces.begin(), _targetedNamespaces.end(), nss) !=
            _targetedNamespaces.end();
    };

    if (s == ErrorCodes::StaleDbVersion) {
        auto si = s.extraInfo<StaleDbRoutingVersion>();
        tassert(6375903, "StaleDbVersion must have extraInfo", si);
        _catalogCache->onStaleDatabaseVersion(si->getDb(), si->getVersionWanted());
    } else if (s == ErrorCodes::StaleConfig) {
        auto si = s.extraInfo<StaleConfigInfo>();
        tassert(6375904, "StaleConfig must have extraInfo", si);
        const auto staleNs = si->getNss();

        if (!isNssInvolvedInRouting(staleNs)) {
            uassertStatusOK(s);
        }

        // Refresh the view namespace if the stale namespace is a buckets timeseries collection.
        if (staleNs.isTimeseriesBucketsCollection()) {
            // A timeseries might've been created, so we need to invalidate the original namespace
            // version.
            _catalogCache->onStaleCollectionVersion(staleNs.getTimeseriesViewNamespace(),
                                                    boost::none);
        }

        // Refresh the timeseries buckets nss when the command targets the buckets collection but
        // the stale namespace is it's view.
        std::for_each(
            _targetedNamespaces.begin(), _targetedNamespaces.end(), [&](const auto& targetedNss) {
                if (targetedNss.isTimeseriesBucketsCollection() &&
                    targetedNss.getTimeseriesViewNamespace() == staleNs) {
                    _catalogCache->onStaleCollectionVersion(targetedNss, boost::none);
                }
            });

        _catalogCache->onStaleCollectionVersion(staleNs, si->getVersionWanted());
    } else if (s == ErrorCodes::StaleEpoch) {
        if (auto si = s.extraInfo<StaleEpochInfo>()) {
            if (!isNssInvolvedInRouting(si->getNss())) {
                uassertStatusOK(s);
            }

            _catalogCache->onStaleCollectionVersion(si->getNss(), si->getVersionWanted());
        } else {
            for (const auto& nss : _targetedNamespaces) {
                _catalogCache->onStaleCollectionVersion(nss, boost::none);
            }
        }
    } else if (s == ErrorCodes::TransactionParticipantFailedUnyield) {
        auto extraInfo = s.extraInfo<TransactionParticipantFailedUnyieldInfo>();
        tassert(9690300, "TransactionParticipantFailedUnyield must have extraInfo", extraInfo);

        auto originalStatus = extraInfo->getOriginalResponseStatus();

        if (!originalStatus || originalStatus->isOK()) {
            uassertStatusOK(s);
        }

        if (*originalStatus == ErrorCodes::StaleConfig) {
            auto si = originalStatus->extraInfo<StaleConfigInfo>();
            tassert(9690301, "StaleConfig must have extraInfo", si);
            _catalogCache->onStaleCollectionVersion(si->getNss(), si->getVersionWanted());
        } else if (*originalStatus == ErrorCodes::StaleDbVersion) {
            auto si = originalStatus->extraInfo<StaleDbRoutingVersion>();
            tassert(9690302, "StaleDbVersion must have extraInfo", si);
            _catalogCache->onStaleDatabaseVersion(si->getDb(), si->getVersionWanted());
        }

        uassertStatusOK(s);
    } else if (s == ErrorCodes::ShardNotFound) {
        // Shard has been removed. Attempting to route again.
        for (const auto& nss : _targetedNamespaces) {
            _catalogCache->onStaleCollectionVersion(nss, boost::none);
            _catalogCache->onStaleDatabaseVersion(nss.dbName(), boost::none);
        }
    } else if (s == ErrorCodes::ShardCannotRefreshDueToLocksHeld) {
        // The shard is stale but it was not allowed to retry from the ServiceEntryPoint. For
        // instance, a getMore command can't be individually retried, therefore we must retry the
        // entire operation from this point.

    } else {
        uassertStatusOK(s);
    }

    // It is not safe to retry stale errors if running in a transaction.
    if (auto txnRouter = TransactionRouter::get(opCtx)) {
        uassertStatusOK(s);
    }

    int maxNumStaleVersionRetries = gMaxNumStaleVersionRetries.load();
    if (++retryInfo->numAttempts > maxNumStaleVersionRetries) {
        uassertStatusOKWithContext(s,
                                   str::stream()
                                       << "Exceeded maximum number of " << maxNumStaleVersionRetries
                                       << " retries attempting \'" << retryInfo->comment << "\'");
    } else {
        LOGV2_DEBUG(6375906,
                    3,
                    "Retrying collection routing operation",
                    "attempt"_attr = retryInfo->numAttempts,
                    "comment"_attr = retryInfo->comment,
                    "status"_attr = s);
    }
}

CollectionRoutingInfo CollectionRouterCommon::_getRoutingInfo(OperationContext* opCtx,
                                                              const NamespaceString& nss) {
    // When in a multi-document transaction, allow getting routing info from the CatalogCache even
    // though locks may be held. The CatalogCache will throw CannotRefreshDueToLocksHeld if the
    // entry is not already cached.
    //
    // Note that we only do this if we indeed hold a lock. Otherwise first executions on a mongos
    // would cause this to unnecessarily throw a transient CannotRefreshDueToLocksHeld error.
    const auto allowLocks =
        opCtx->inMultiDocumentTransaction() && shard_role_details::getLocker(opCtx)->isLocked();

    // Call getCollectionRoutingInfoAt if we need to read the CollectionRoutingInfo at a specific
    // point in time. Otherwise just return the most recent one.
    auto maybeAtClusterTime = repl::ReadConcernArgs::get(opCtx).getArgsAtClusterTime();
    if (!maybeAtClusterTime && TransactionRouter::get(opCtx)) {
        maybeAtClusterTime = TransactionRouter::get(opCtx).getSelectedAtClusterTime();
    }

    if (maybeAtClusterTime) {
        return uassertStatusOK(_catalogCache->getCollectionRoutingInfoAt(
            opCtx, nss, maybeAtClusterTime->asTimestamp(), allowLocks));
    }
    return uassertStatusOK(_catalogCache->getCollectionRoutingInfo(opCtx, nss, allowLocks));
}

void CollectionRouterCommon::appendCRUDRoutingTokenToCommand(const ShardId& shardId,
                                                             const CollectionRoutingInfo& cri,
                                                             BSONObjBuilder* builder) {
    if (cri.getShardVersion(shardId) == ShardVersion::UNSHARDED()) {
        // Need to add the database version as well.
        const auto& dbVersion = cri.getDbVersion();
        if (!dbVersion.isFixed()) {
            BSONObjBuilder dbvBuilder(builder->subobjStart(DatabaseVersion::kDatabaseVersionField));
            dbVersion.serialize(&dbvBuilder);
        }
    }
    appendShardVersion(*builder, cri.getShardVersion(shardId));
}

CollectionRouter::CollectionRouter(ServiceContext* service, NamespaceString nss)
    : CollectionRouterCommon(Grid::get(service)->catalogCache(), {std::move(nss)}) {}

CollectionRouter::CollectionRouter(CatalogCache* catalogCache, NamespaceString nss)
    : CollectionRouterCommon(catalogCache, {std::move(nss)}) {}

MultiCollectionRouter::MultiCollectionRouter(ServiceContext* service,
                                             const std::vector<NamespaceString>& nssList)
    : CollectionRouterCommon(Grid::get(service)->catalogCache(), nssList) {}

bool MultiCollectionRouter::isAnyCollectionNotLocal(
    OperationContext* opCtx,
    const stdx::unordered_map<NamespaceString, CollectionRoutingInfo>& criMap) {
    auto* grid = Grid::get(opCtx->getServiceContext());
    // By definition, all collections in a non sharded deployment are local.
    if (!(grid->isInitialized() && grid->isShardingInitialized())) {
        return false;
    }

    const auto myShardId = ShardingState::get(opCtx)->shardId();
    bool anyCollectionNotLocal = false;

    // For each collection, figure out if it fully lives on this shard.
    for (const auto& nss : _targetedNamespaces) {
        const auto nssCri = criMap.find(nss);
        tassert(8322001,
                "Must be an entry in criMap for namespace " + nss.toStringForErrorMsg(),
                nssCri != criMap.end());

        const auto atClusterTime = repl::ReadConcernArgs::get(opCtx).getArgsAtClusterTime();
        const auto chunkManagerMaybeAtClusterTime = atClusterTime
            ? ChunkManager::makeAtTime(nssCri->second.getChunkManager(),
                                       atClusterTime->asTimestamp())
            : nssCri->second.getChunkManager();

        bool isNssLocal = [&]() {
            if (chunkManagerMaybeAtClusterTime.isSharded()) {
                return false;
            } else if (chunkManagerMaybeAtClusterTime.isUnsplittable()) {
                return chunkManagerMaybeAtClusterTime.getMinKeyShardIdWithSimpleCollation() ==
                    myShardId;
            } else {
                // If collection is untracked, it is only local if this shard is the dbPrimary
                // shard.
                return nssCri->second.getDbPrimaryShardId() == myShardId;
            }
        }();

        if (!isNssLocal) {
            anyCollectionNotLocal = true;
        }
    }
    return anyCollectionNotLocal;
}
}  // namespace router
}  // namespace sharding
}  // namespace mongo
