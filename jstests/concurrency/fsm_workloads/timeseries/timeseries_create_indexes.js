/**
 * Repeatedly create indexes while dropping and recreating timeseries collections.
 *
 * @tags: [
 *   requires_timeseries,
 *   # TODO SERVER-105509 enable test in config shard suites
 *   config_shard_incompatible,
 * ]
 */

import {uniformDistTransitions} from "jstests/concurrency/fsm_workload_helpers/state_transition_utils.js";
import {TimeseriesTest} from "jstests/core/timeseries/libs/timeseries.js";

const dbPrefix = jsTestName() + "_DB_";
const dbCount = 2;
const collPrefix = "coll_";
const collCount = 2;
const timeFieldName = "time";
const metaFieldName = "meta";

function getRandomDb(db) {
    return db.getSiblingDB(dbPrefix + Random.randInt(dbCount));
}

function getRandomCollection(db) {
    return db[collPrefix + Random.randInt(collCount)];
}

// TODO(SERVER-109819): Remove once v9.0 is last LTS
// Since binary v8.2, index operations either take a single lock, or re-check the UUID when
// re-acquiring the lock and return CollectionUUIDMismatch if the collection was dropped.
// Older binaries don't do this, so they can return more error codes.
const isPreV82Binary =
    TestData.multiversionBinVersion &&
    MongoRunner.compareBinVersions(MongoRunner.getBinVersionFor(TestData.multiversionBinVersion), "8.2") < 0;

export const $config = (function () {
    let data = {nsPrefix: "create_idx_", numCollections: 5};

    let states = {
        createNormalColl: function (db, collname) {
            const coll = getRandomCollection(db);
            assert.commandWorkedOrFailedWithCode(db.createCollection(coll.getName()), [ErrorCodes.NamespaceExists]);
        },
        createTimeseriesColl: function (db, collname) {
            const coll = getRandomCollection(db);
            assert.commandWorkedOrFailedWithCode(
                db.createCollection(coll.getName(), {
                    timeseries: {timeField: timeFieldName, metaField: metaFieldName},
                }),
                [ErrorCodes.NamespaceExists],
            );
        },
        insert: function (db, collName) {
            const coll = getRandomCollection(db);
            assert.commandWorkedOrFailedWithCode(
                coll.insert({
                    measurement: "measurement",
                    time: ISODate(),
                }),
                [
                    // The collection has been dropped and re-created as non-timeseries
                    // during the insert.
                    // TODO (SERVER-85548): revisit 85557* error codes
                    8555700,
                    8555701,
                    // The collection did not originally exist but has been created as a time-series
                    // collection during our insert.
                    10685100,
                    // The collection has been dropped and re-created as a time-series collection
                    // during our insert.
                    10685101,
                    // Collection UUID changed during insert 974880*
                    9748800,
                    9748801,
                    9748802,
                    // If the collection already exists and is a view
                    // TODO SERVER-85548 this should never happen
                    ErrorCodes.NamespaceExists,
                    // TODO SERVER-85548 this should never happen
                    ErrorCodes.CommandNotSupportedOnView,
                    // The buckets collection gets dropped while translating namespace
                    // from timeseries view.
                    // TODO SERVER-85548 remove after legacy timeseries
                    ErrorCodes.NamespaceNotFound,
                    ErrorCodes.NoProgressMade,
                    // Can occur when mongos exhausts its retries on StaleConfig errors from the
                    // shard and returns the StaleConfig error to the client.
                    ErrorCodes.StaleConfig,
                ],
            );
        },
        drop: function (db, collName) {
            const coll = getRandomCollection(db);
            coll.drop();
        },
        createIndex: function (db, collName) {
            const allIndexSpecs = [{[metaFieldName]: 1}, {[timeFieldName]: 1}, {"measurement": 1}, {"other": 1}];

            const coll = getRandomCollection(db);
            const indexSpec = allIndexSpecs[Math.floor(Math.random() * allIndexSpecs.length)];

            jsTest.log(`Creating index '${tojsononeline(indexSpec)}' on ${coll.getFullName()}`);
            assert.commandWorkedOrFailedWithCode(coll.createIndex(indexSpec), [
                // The collection has been concurrently dropped and recreated
                ErrorCodes.CollectionUUIDMismatch,
                ...(isPreV82Binary ? [ErrorCodes.IllegalOperation] : []),
                ErrorCodes.IndexBuildAborted,
                // If the collection already exists and is a view
                // TODO SERVER-85548 this should never happen
                ErrorCodes.NamespaceExists,
                // TODO SERVER-85548 this should never happen
                ErrorCodes.CommandNotSupportedOnView,
                // The buckets collection gets dropped while translating namespace
                // from timeseries view.
                // TODO SERVER-85548 remove after legacy timeseries
                ErrorCodes.NamespaceNotFound,
                // The buckets collection gets dropped and re-created as non-timeseries
                // during index build.
                5993303,
                // Encountered when two threads execute concurrently and repeatedly create
                // collection (as part of createIndexes) and drop collection
                ErrorCodes.CannotImplicitlyCreateCollection,
                // TODO SERVER-104712 remove the following exected error
                10195200,
                // Can occur when mongos exhausts its retries on StaleConfig errors from the shard
                // and returns the StaleConfig error to the client.
                ErrorCodes.StaleConfig,
            ]);
        },
        checkIndexes: function (db, collName) {
            const coll = getRandomCollection(db);
            let indexes;
            try {
                indexes = coll.getIndexes();
            } catch (err) {
                if (isPreV82Binary && err.code == ErrorCodes.CommandNotSupportedOnView) {
                    return;
                }
                throw err;
            }
            indexes.forEach((index) => {
                Object.keys(index.key).forEach((indexKey) => {
                    assert(
                        !indexKey.startsWith("control."),
                        `Found buckets index spec on timeseries collection ${coll.getName()}: ${tojson(index)}`,
                    );
                });
            });
        },
    };

    return {
        threadCount: 12,
        iterations: 1000,
        states: states,
        startState: "createTimeseriesColl",
        transitions: uniformDistTransitions(states),
    };
})();
