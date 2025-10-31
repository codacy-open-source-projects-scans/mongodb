/**
 * Verifies that successful commits of addShard generate the expected metadata on config.placementHistory.
 *
 * @tags: [
 *   featureFlagChangeStreamPreciseShardTargeting,
 * ]
 */
import {ReplSetTest} from "jstests/libs/replsettest.js";
import {ShardingTest} from "jstests/libs/shardingtest.js";

import {afterEach, before, beforeEach, describe, it} from "jstests/libs/mochalite.js";

describe("Activity of the addShard commit within config.placementHistory", function () {
    before(() => {
        this.initMetadataDocNssId = "";

        this.spinNewReplicaSet = function (rsName) {
            const newReplicaSet = new ReplSetTest({name: rsName, nodes: 1});
            newReplicaSet.startSet({shardsvr: ""});
            newReplicaSet.initiate();
            this.newReplicaSets.push(newReplicaSet);
            return newReplicaSet;
        };

        this.getTopologyTimeOf = function (shardName) {
            const shardDoc = this.st.config.shards.findOne({_id: shardName});
            return shardDoc.topologyTime;
        };

        this.verifyPlacementHistoryInitMetadata = function (initializationTime, fallbackResponse) {
            const initMetadataDocs = this.st.config.placementHistory
                .find({nss: this.initMetadataDocNssId})
                .sort({timestamp: 1})
                .toArray();
            assert.eq(2, initMetadataDocs.length);

            const earliestPITDescriptor = initMetadataDocs[1];
            const fallbackResponseDescriptor = initMetadataDocs[0];

            assert.sameMembers(earliestPITDescriptor.shards, []);
            assert(timestampCmp(earliestPITDescriptor.timestamp, initializationTime) === 0);

            assert.sameMembers(fallbackResponseDescriptor.shards, fallbackResponse);
            assert(timestampCmp(fallbackResponseDescriptor.timestamp, Timestamp(0, 1)) === 0);
        };
    });

    beforeEach(() => {
        this.st = new ShardingTest({
            name: "addShardHistoricalPlacementMetadataTest",
            shards: 0,
            mongos: 1,
            config: {nodes: 1},
            other: {useHostname: true},
        });
        this.newReplicaSets = [];
    });

    afterEach(() => {
        this.st.stop();
        this.st = null;
        this.newReplicaSets.forEach((rs) => rs.stopSet());
        this.newReplicaSets = [];
    });

    it("No document is present in config.placementHistory before the first shard registration", () => {
        assert.eq(0, this.st.config.placementHistory.countDocuments({}));
    });

    it("addShard generates initialization metadata when a first empty shard is added", () => {
        const firstShardName = "firstShard";
        const firstShardRS = this.spinNewReplicaSet(firstShardName);

        assert.commandWorked(this.st.s.adminCommand({addShard: firstShardRS.getURL(), name: firstShardName}));

        const firstShardCreationTime = this.getTopologyTimeOf(firstShardName);
        this.verifyPlacementHistoryInitMetadata(firstShardCreationTime, [firstShardName]);
    });

    it("transitionFromDedicatedConfigServer generates initialization metadata", () => {
        const configShardName = "config";
        assert.commandWorked(this.st.s.adminCommand({transitionFromDedicatedConfigServer: 1}));
        const firstShardCreationTime = this.getTopologyTimeOf(configShardName);
        this.verifyPlacementHistoryInitMetadata(firstShardCreationTime, [configShardName]);
    });

    it("addShard preserves the original initialization metadata when a second shard is added", () => {
        const firstShardName = "firstShard";
        const firstShardRS = this.spinNewReplicaSet(firstShardName);

        assert.commandWorked(this.st.s.adminCommand({addShard: firstShardRS.getURL(), name: firstShardName}));
        const firstShardCreationTime = this.getTopologyTimeOf(firstShardName);

        const secondShardName = "secondShard";
        const secondShardRS = this.spinNewReplicaSet(secondShardName);
        assert.commandWorked(this.st.s.adminCommand({addShard: secondShardRS.getURL(), name: secondShardName}));

        this.verifyPlacementHistoryInitMetadata(firstShardCreationTime, [firstShardName]);
    });

    it("addShard generates initialization metadata and placement documents when a first not-empty shard is added", () => {
        const firstShardName = "firstShard";
        const firstShardRS = this.spinNewReplicaSet(firstShardName);

        // Pre-populate two databases, each owning a collection.
        const dbNames = ["testDB1", "testDB2"];
        const collName = "coll";
        for (const dbName of dbNames) {
            const db = firstShardRS.getPrimary().getDB(dbName);
            assert.commandWorked(db.runCommand({create: collName}));
        }

        assert.commandWorked(this.st.s.adminCommand({addShard: firstShardRS.getURL(), name: firstShardName}));
        const firstShardCreationTime = this.getTopologyTimeOf(firstShardName);

        // A placement entry should have ben generated for each database (while untracked collections are ignored).
        assert.eq(dbNames.length + 2 /*initMetadataDocs*/, this.st.config.placementHistory.countDocuments({}));
        for (const dbName of dbNames) {
            const placementDocs = this.st.config.placementHistory.find({nss: dbName}).toArray();
            assert.eq(1, placementDocs.length);
            assert.sameMembers(placementDocs[0].shards, [firstShardName]);
            assert(timestampCmp(placementDocs[0].timestamp, firstShardCreationTime) === 0);
        }

        this.verifyPlacementHistoryInitMetadata(firstShardCreationTime, [firstShardName]);
    });
});
