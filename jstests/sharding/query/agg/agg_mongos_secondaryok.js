/**
 * Tests aggregate command against mongos with secondaryOk. For more tests on read preference,
 * please refer to jstests/sharding/read_pref_cmd.js.
 * @tags: [
 *   requires_replication,
 *   requires_sharding,
 *   requires_profiling,
 * ]
 */
import {ShardingTest} from "jstests/libs/shardingtest.js";
import {awaitRSClientHosts} from "jstests/replsets/rslib.js";

var NODES = 2;

var doTest = function(st, doSharded) {
    var testDB = st.s.getDB('test');

    if (doSharded) {
        testDB.adminCommand({enableSharding: 'test'});
        testDB.adminCommand({shardCollection: 'test.user', key: {x: 1}});
    }

    testDB.user.insert({x: 10}, {writeConcern: {w: NODES}});
    testDB.setSecondaryOk();

    var secNode = st.rs0.getSecondary();
    secNode.getDB('test').setProfilingLevel(2);

    // wait for mongos to recognize that the secondary is up
    awaitRSClientHosts(st.s, secNode, {ok: true});

    var res = testDB.runCommand({aggregate: 'user', pipeline: [{$project: {x: 1}}], cursor: {}});
    assert(res.ok, 'aggregate command failed: ' + tojson(res));

    var profileQuery = {op: 'command', ns: 'test.user', 'command.aggregate': 'user'};
    var profileDoc = secNode.getDB('test').system.profile.findOne(profileQuery);

    assert(profileDoc != null);
    testDB.dropDatabase();
};

var st = new ShardingTest({shards: {rs0: {oplogSize: 10, nodes: NODES}}});

doTest(st, false);
doTest(st, true);

st.stop();