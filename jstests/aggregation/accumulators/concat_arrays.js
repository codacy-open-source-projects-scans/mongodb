/**
 * Basic tests for the $concatArrays accumulator.
 * @tags: [featureFlagArrayAccumulators, requires_fcv_81]
 */
import {assertErrorCode} from "jstests/aggregation/extras/utils.js";

const coll = db["accumulators_concat_arrays"];
assert(coll.drop());

// Test that $concatArrays correctly concatenates arrays, preserves sort order and preserves order
// of the elements inside the concatenated arrays.
assert.commandWorked(coll.insert([
    {_id: 0, author: "Adrian", publisher: "Pub1", books: ["Adrian Book 0", "Adrian Book 1"]},
    {_id: 1, author: "Militsa", publisher: "Pub1", books: ["Militsa Book 0"]},
    {_id: 2, author: "Hana", publisher: "Pub1", books: ["Hana Book 0", "Hana Book 1"]},
]));

let result = coll.aggregate([
                     {$match: {_id: {$in: [0, 1, 2]}}},
                     {$sort: {_id: 1}},
                     {$group: {_id: null, allBooks: {$concatArrays: '$books'}}}
                 ])
                 .toArray();

assert.eq(
    result, [{
        _id: null,
        allBooks:
            ["Adrian Book 0", "Adrian Book 1", "Militsa Book 0", "Hana Book 0", "Hana Book 1"]
    }]);

// Redo the aggregation with the reverse sort to ensure sort order is really preserverd and we're
// not just looking at the docs in the order they are found in the collection.
result = coll.aggregate([
                 {$match: {_id: {$in: [0, 1, 2]}}},
                 {$sort: {_id: -1}},
                 {$group: {_id: null, allBooks: {$concatArrays: '$books'}}}
             ])
             .toArray();

assert.eq(
    result, [{
        _id: null,
        allBooks:
            ["Hana Book 0", "Hana Book 1", "Militsa Book 0", "Adrian Book 0", "Adrian Book 1"]
    }]);

// $concatArrays should concatenate arrays, and any nested arrays should remain array values.
assert.commandWorked(coll.insert({
    _id: 3,
    author: "Ben",
    publisher: "Pub2",
    books:
        [["Ben Series 0 Book 0", "Ben Series 0 Book 1"], ["Ben Series 1 Book 0"], "Ben Book 4"]
}));
result = coll.aggregate([
                 {$match: {_id: {$in: [1, 3]}}},
                 {$sort: {_id: 1}},
                 {$group: {_id: null, allBooks: {$concatArrays: '$books'}}}
             ])
             .toArray();
assert.eq(result, [{
              _id: null,
              allBooks: [
                  "Militsa Book 0",
                  ["Ben Series 0 Book 0", "Ben Series 0 Book 1"],
                  ["Ben Series 1 Book 0"],
                  "Ben Book 4"
              ]
          }]);

// $concatArrays should 'skip over' documents that do not have field.
// Importantly, do not create a null element for documents that do not have the referenced field.
assert.commandWorked(coll.insert([
    {_id: 4, author: "Nick", publisher: "Pub3", books: ["Smile :)"]},
    {_id: 5, author: "Santiago", publisher: "Pub3"},
    {_id: 6, author: "Matt", publisher: "Pub3", books: ["Happy!"]}
]));
result = coll.aggregate([
                 {$match: {_id: {$in: [4, 5, 6]}}},
                 {$sort: {_id: 1}},
                 {$group: {_id: null, allBooks: {$concatArrays: '$books'}}}
             ])
             .toArray();
assert.eq(result, [{_id: null, allBooks: ["Smile :)", "Happy!"]}]);

// Test for errors on non-array types ($concatArrays only supports arrays).
const notArrays = [1, "string", {object: "object"}, null];

for (const notAnArray of notArrays) {
    assert.commandWorked(coll.insert([{
        _id: "doesNotMatter",
        author: "doesNotMatter",
        publisher: "doesNotMatter",
        books: notAnArray
    }]));

    assertErrorCode(coll,
                    [{$group: {_id: null, allBooks: {$concatArrays: '$books'}}}],
                    ErrorCodes.TypeMismatch);

    assert.commandWorked(coll.deleteOne({_id: "doesNotMatter"}));
}

// Basic test of $concatArrays with grouping.
result = coll.aggregate([
                 {$match: {_id: {$in: [0, 1, 3]}}},
                 {$sort: {_id: 1}},
                 {$group: {_id: '$publisher', booksByPublisher: {$concatArrays: '$books'}}},
                 {$sort: {_id: 1}}
             ])
             .toArray();
assert.eq(result, [
    {_id: "Pub1", booksByPublisher: ["Adrian Book 0", "Adrian Book 1", "Militsa Book 0"]},
    {
        _id: "Pub2",
        booksByPublisher:
            [["Ben Series 0 Book 0", "Ben Series 0 Book 1"], ["Ben Series 1 Book 0"], "Ben Book 4"]
    },
]);