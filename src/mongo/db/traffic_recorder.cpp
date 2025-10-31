/**
 *    Copyright (C) 2018-present MongoDB, Inc.
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

#include "mongo/db/traffic_recorder.h"

#include "mongo/base/data_builder.h"
#include "mongo/base/data_range_cursor.h"
#include "mongo/base/data_type_endian.h"
#include "mongo/base/data_type_terminated.h"
#include "mongo/base/error_codes.h"
#include "mongo/base/initializer.h"
#include "mongo/base/status.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/bsonelement.h"
#include "mongo/bson/bsonmisc.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/db/commands/server_status/server_status.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/query/util/stop_token.h"
#include "mongo/db/server_options.h"
#include "mongo/db/service_context.h"
#include "mongo/db/traffic_recorder.h"
#include "mongo/db/traffic_recorder_gen.h"
#include "mongo/db/traffic_recorder_session_utils.h"
#include "mongo/logv2/log.h"
#include "mongo/platform/atomic_word.h"
#include "mongo/stdx/thread.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/concurrency/thread_name.h"
#include "mongo/util/decorable.h"
#include "mongo/util/duration.h"
#include "mongo/util/functional.h"
#include "mongo/util/net/hostandport.h"
#include "mongo/util/producer_consumer_queue.h"
#include "mongo/util/tick_source.h"
#include "mongo/util/time_support.h"
#include "mongo/util/uuid.h"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <filesystem>
#include <limits>
#include <memory>
#include <queue>
#include <string>
#include <tuple>
#include <utility>

#include <absl/crc/crc32c.h>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/none.hpp>
#include <fmt/ostream.h>

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kRecorder


namespace mongo {

void appendPacketHeader(DataBuilder& db, const TrafficRecordingPacket& packet) {
    db.clear();
    Message toWrite = packet.message;

    uassertStatusOK(db.writeAndAdvance<LittleEndian<uint32_t>>(0));
    uassertStatusOK(db.writeAndAdvance<EventType>(packet.eventType));
    uassertStatusOK(db.writeAndAdvance<LittleEndian<uint64_t>>(packet.id));
    uassertStatusOK(db.writeAndAdvance<Terminated<'\0', StringData>>(StringData(packet.session)));
    uassertStatusOK(
        db.writeAndAdvance<LittleEndian<uint64_t>>(durationCount<Microseconds>(packet.offset)));
    uassertStatusOK(db.writeAndAdvance<LittleEndian<uint64_t>>(packet.order));

    auto fullSize = db.size() + packet.message.size();
    db.getCursor().write<LittleEndian<uint32_t>>(fullSize);
}

TrafficRecorder::RecordingID generateID() {
    return UUID::gen().toString();
}

TrafficRecorder::Recording::Recording(const StartTrafficRecording& options,
                                      std::filesystem::path globalRecordingDirectory,
                                      TickSource* tickSource)
    : _path(_getPath(globalRecordingDirectory, std::string{options.getDestination()})),
      _maxLogSize(options.getMaxFileSize()),
      _tickSource(tickSource) {

    if (auto id = options.getRecordingID()) {
        _id = RecordingID(*id);
    } else {
        _id = generateID();
    }

    // Scheduled times can be provided to startTrafficRecording.
    auto start = options.getStartTime();
    auto end = options.getEndTime();

    // Both or neither must be provided; validated in the command.
    tassert(10849407,
            "startTrafficRecording should enforce providing both start and end time, or neither",
            start.has_value() == end.has_value());

    if (start) {
        _scheduledTimes = std::pair(*start, *end);
    }

    MultiProducerSingleConsumerQueue<TrafficRecordingPacket, CostFunction>::Options queueOptions;
    queueOptions.maxQueueDepth = options.getMaxMemUsage();
    _pcqPipe =
        MultiProducerSingleConsumerQueue<TrafficRecordingPacket, CostFunction>::Pipe(queueOptions);

    _trafficStats.setBufferSize(options.getMaxMemUsage());
    _trafficStats.setRecordingDir(_path);
    _trafficStats.setMaxFileSize(_maxLogSize);
}

void TrafficRecorder::Recording::start() {
    _started.store(true);
    _trafficStats.setRunning(true);
    startTime.store(_tickSource->ticksTo<Microseconds>(_tickSource->getTicks()));
    _thread = stdx::thread([consumer = std::move(_pcqPipe.consumer), this] {
        if (!boost::filesystem::is_directory(boost::filesystem::absolute(_path))) {
            boost::filesystem::create_directory(boost::filesystem::absolute(_path));
        }

        static const std::string checkSumFileName = "checksum.txt";
        boost::filesystem::path checksumFile(boost::filesystem::absolute(_path));
        checksumFile /= checkSumFileName;
        boost::filesystem::ofstream checksumOut(checksumFile,
                                                std::ios_base::app | std::ios_base::out);

        // The calculator calculates the checksum of each recording for integrity check.
        absl::crc32c_t checksum{0};
        auto writeChecksum = [&checksumOut, &checksum](const std::string& recordingFile) {
            fmt::print(checksumOut, "{}\t{:x}\n", recordingFile, static_cast<uint32_t>(checksum));
            checksum = absl::crc32c_t{0};
        };

        // This function guarantees to open a new recording file. Force the thread to sleep for
        // a very short period of time if a file with the same name exists and then create a new
        // file. This case is rare and only happens when the 'maxFileSize' is too small. The
        // same recording file could be opened twice within 1 millisecond.
        auto openNewRecordingFile = [this](boost::filesystem::path& recordingFile,
                                           boost::filesystem::ofstream& out) {
            recordingFile = boost::filesystem::absolute(_path);
            recordingFile /= std::to_string(Date_t::now().toMillisSinceEpoch());
            recordingFile += ".bin";
            while (boost::filesystem::exists(recordingFile)) {
                stdx::this_thread::sleep_for(stdx::chrono::milliseconds(5));
                recordingFile = boost::filesystem::absolute(_path);
                recordingFile /= std::to_string(Date_t::now().toMillisSinceEpoch());
                recordingFile += ".bin";
            }
            out.open(recordingFile,
                     std::ios_base::binary | std::ios_base::trunc | std::ios_base::out);
        };
        boost::filesystem::path recordingFile;
        boost::filesystem::ofstream out;
        try {
            DataBuilder db;
            openNewRecordingFile(recordingFile, out);

            while (true) {
                std::deque<TrafficRecordingPacket> storage;
                size_t bytes;

                std::tie(storage, bytes) = consumer.popManyUpTo(MaxMessageSizeBytes);

                // if this fired... somehow we got a message bigger than a message
                invariant(bytes);

                for (const auto& packet : storage) {
                    appendPacketHeader(db, packet);
                    Message toWrite = packet.message;

                    auto size = db.size() + toWrite.size();

                    bool maxSizeExceeded = false;

                    {
                        stdx::lock_guard<stdx::mutex> lk(_mutex);
                        _written += size;
                        maxSizeExceeded = _written >= _maxLogSize;
                    }

                    if (maxSizeExceeded) {
                        writeChecksum(recordingFile.string());
                        out.close();
                        // The current recording file hits the maximum file size, open a new
                        // recording file.
                        openNewRecordingFile(recordingFile, out);
                        // We assume that the size of one packet message is greater than the max
                        // file size. It's intentional to not assert if
                        // 'size' >= '_maxLogSize' for testing purposes.
                        {
                            stdx::lock_guard<stdx::mutex> lk(_mutex);
                            _written = size;
                        }
                    }

                    out.write(db.getCursor().data(), db.size());
                    absl::ExtendCrc32c(checksum, {db.getCursor().data(), db.size()});
                    out.write(toWrite.buf(), toWrite.size());
                    absl::ExtendCrc32c(checksum,
                                       {toWrite.buf(), static_cast<size_t>(toWrite.size())});
                }
            }
        } catch (const ExceptionFor<ErrorCodes::ProducerConsumerQueueConsumed>&) {
            // Close naturally
            writeChecksum(recordingFile.string());
        } catch (...) {
            writeChecksum(recordingFile.string());
            auto status = exceptionToStatus();

            stdx::lock_guard<stdx::mutex> lk(_mutex);
            _result = status;
        }
    });
}

bool TrafficRecorder::Recording::pushRecord(const uint64_t id,
                                            const std::string session,
                                            Microseconds offset,
                                            const uint64_t& order,
                                            const Message& message,
                                            EventType eventType) {
    try {
        _pcqPipe.producer.push({eventType, id, session, offset, order, message});
        return true;
    } catch (const ExceptionFor<ErrorCodes::ProducerConsumerQueueProducerQueueDepthExceeded>&) {
        // If we couldn't push our packet begin the process of failing the recording
        _pcqPipe.producer.close();

        stdx::lock_guard<stdx::mutex> lk(_mutex);

        // If the result was otherwise okay, mark it as failed due to the queue blocking.  If
        // it failed for another reason, don't overwrite that.
        if (_result.isOK()) {
            _result = Status(ErrorCodes::Error(51061), "queue was blocked in traffic recorder");
        }
    } catch (const ExceptionFor<ErrorCodes::ProducerConsumerQueueEndClosed>&) {
    }

    return false;
}

Status TrafficRecorder::Recording::shutdown() {
    stdx::unique_lock<stdx::mutex> lk(_mutex);

    if (!_inShutdown) {
        _inShutdown = true;
        lk.unlock();

        _pcqPipe.producer.close();
        if (_thread.joinable()) {
            _thread.join();
        }

        lk.lock();
    }

    return _result;
}

BSONObj TrafficRecorder::Recording::getStats() {
    stdx::lock_guard<stdx::mutex> lk(_mutex);
    _trafficStats.setBufferedBytes(_pcqPipe.controller.getStats().queueDepth);
    _trafficStats.setCurrentFileSize(_written);
    return _trafficStats.toBSON();
}

std::string TrafficRecorder::Recording::_getPath(std::filesystem::path globalRecordingDirectory,
                                                 const std::string& recordingSubdir) {
    uassert(ErrorCodes::BadValue,
            "Traffic recording destination must have a non-empty value",
            !recordingSubdir.empty());

    // Normalise as directory with trailing "/"
    globalRecordingDirectory = globalRecordingDirectory.concat("/").lexically_normal();

    auto path = globalRecordingDirectory / recordingSubdir;

    uassert(ErrorCodes::BadValue,
            "Traffic recording filename must be a simple filename",
            path.parent_path().concat("/") == globalRecordingDirectory);

    return path.string();
}


namespace {
static const auto getTrafficRecorder = ServiceContext::declareDecoration<TrafficRecorder>();
}  // namespace

TrafficRecorder& TrafficRecorder::get(ServiceContext* svc) {
    return getTrafficRecorder(svc);
}

TrafficRecorder::~TrafficRecorder() {}

std::shared_ptr<TrafficRecorder::Recording> TrafficRecorder::_makeRecording(
    const StartTrafficRecording& options,
    std::filesystem::path globalRecordingDirectory,
    TickSource* tickSource) const {
    return std::make_shared<Recording>(options, globalRecordingDirectory, tickSource);
}

StartReply TrafficRecorder::start(const StartTrafficRecording& options, ServiceContext* svcCtx) {
    uassert(ErrorCodes::BadValue,
            "startTime and endTime should both be provided, or neither",
            options.getStartTime().has_value() == options.getEndTime().has_value());

    if (options.getStartTime().has_value()) {
        auto start = *options.getStartTime();
        auto end = *options.getEndTime();

        uassert(ErrorCodes::BadValue,
                "startTime should be in the future, and less than 1 day into the future",
                start > Date_t::now() && start < (Date_t::now() + Days(1)));


        uassert(ErrorCodes::BadValue,
                "endTime should be after startTime, and less than 10 days into the future",
                end > start && end < (Date_t::now() + Days(10)));
    }

    // May throw if not in a valid state to create a new recording i.e., if a pending or running
    // recording already exists.
    auto [rec, created] = _prepare(options, svcCtx);
    const auto recID = (*rec)->getID();
    if (!created) {
        // This request did not need to create a new recording - it is a repeated call with the same
        // recording ID. No further action needs to be taken.
        auto status =
            (*rec)->isStarted() ? RecordingStateEnum::Running : RecordingStateEnum::Scheduled;
        return {recID, false, status};
    }
    if (!options.getStartTime().has_value()) {
        // Start immediately.
        _start(std::move(rec), svcCtx);
        return {recID, true, RecordingStateEnum::Running};
    }

    auto start = *options.getStartTime();
    auto end = *options.getEndTime();

    // A recording has been created, but needs to start (and stop) at times in the future.
    // Create a task to do so.

    LOGV2_INFO(10849400, "Recording Scheduled for", "time"_attr = start.toString());

    std::shared_ptr<Recording> expectedRecording = *rec;

    if (_worker) {
        // If a previous scheduled recording still has tasks waiting to run, cancel them.
        // They would be no-ops, but can be eagerly cleaned up.
        _worker->cancelAll();
    } else {
        // Initialize the task worker.
        _worker = makeTaskScheduler("TrafficRecorderScheduler");
    }

    _worker->runAt(start, [expectedRecording, this, svcCtx]() {
        auto rec = _recording.synchronize();
        if (*rec != expectedRecording) {
            LOGV2_INFO(10849401,
                       "Scheduled recording start skipped as recording not in expected state");
            return;
        }
        try {
            _start(std::move(rec), svcCtx);
        } catch (const std::exception& e) {
            LOGV2_ERROR(
                10849402, "Scheduled recording could not be started", "exception"_attr = e.what());
            return;
        }
        LOGV2_INFO(10849403, "Scheduled recording started");
    });

    _worker->runAt(end, [expectedRecording, this, svcCtx]() {
        auto rec = _recording.synchronize();
        if (*rec != expectedRecording) {
            LOGV2_INFO(10849404,
                       "Scheduled recording end skipped as recording not in expected state");
            return;
        }

        try {
            _stop(std::move(rec), svcCtx);
        } catch (const DBException& e) {
            LOGV2_ERROR(
                10849405, "Scheduled recording could not be stopped", "exception"_attr = e.what());
            return;
        }
        LOGV2_INFO(10849406, "Recording Stopped");
    });
    return {recID, true, RecordingStateEnum::Scheduled};
}

void TrafficRecorder::stop(ServiceContext* svcCtx) {
    // The recording may have been a scheduled recording.
    // This explicit stop command should cancel any outstanding tasks.
    if (_worker) {
        _worker->cancelAll();
    }
    _stop(_recording.synchronize(), svcCtx);
}

StatusReply TrafficRecorder::status() const {
    auto rec = _recording.synchronize();
    StatusReply res;

    auto recPtr = *rec;
    if (!recPtr) {
        res.setStatus(RecordingStateEnum::None);
        return res;
    }
    res.setStatus(recPtr->isStarted() ? RecordingStateEnum::Running
                                      : RecordingStateEnum::Scheduled);
    res.setRecordingID(recPtr->getID());
    return res;
}

void TrafficRecorder::sessionStarted(const transport::Session& ts) {
    auto id = ts.id();
    auto session = ts.toBSON().toString();
    _observe(id, session, Message(), EventType::kSessionStart);
}
void TrafficRecorder::sessionEnded(const transport::Session& ts) {
    auto id = ts.id();
    auto session = ts.toBSON().toString();
    _observe(id, session, Message(), EventType::kSessionEnd);
}

void TrafficRecorder::observe(const transport::Session& ts,
                              const Message& message,
                              EventType eventType) {
    _observe(ts.id(), ts.toBSON().toString(), message, eventType);
}

void TrafficRecorder::_observe(uint64_t id,
                               const std::string& session,
                               const Message& message,
                               EventType eventType) {
    if (!_shouldRecord.load()) {
        return;
    }

    auto recording = _getCurrentRecording();

    // If we don't have an active recording, bail
    if (!recording) {
        return;
    }

    _observe(*recording, id, session, message, eventType);
}

void TrafficRecorder::_observe(Recording& recording,
                               uint64_t id,
                               const std::string& session,
                               const Message& message,
                               EventType eventType) {

    auto* tickSource = recording.getTickSource();
    // Try to record the message
    if (recording.pushRecord(id,
                             session,
                             tickSource->ticksTo<Microseconds>(tickSource->getTicks()) -
                                 recording.startTime.load(),
                             recording.order.addAndFetch(1),
                             message,
                             eventType)) {
        return;
    }

    // If the recording isn't the one we have in hand bail (its been ended, or a new one has
    // been created
    if (_recording->get() != &recording) {
        return;
    }

    // We couldn't queue and it's still our recording.  No one else should try to queue
    _shouldRecord.store(false);
}


std::pair<TrafficRecorder::LockedRecordingHandle, bool> TrafficRecorder::_prepare(
    const StartTrafficRecording& options, ServiceContext* svcCtx) {
    auto globalRecordingDirectory = gTrafficRecordingDirectory;
    uassert(ErrorCodes::BadValue,
            "Traffic recording directory not set",
            !globalRecordingDirectory.empty());

    auto rec = _recording.synchronize();
    auto recPtr = *rec;
    auto requestedID = options.getRecordingID();

    if (recPtr) {
        // A recording already exists.
        if (requestedID.has_value()) {
            // A recording exists, and the request provided a recording ID.
            // If the current recording has the same ID, the start request should complete
            // successfully without taking further action, else it should fail.
            uassert(ErrorCodes::BadValue,
                    "Traffic recording already active with a different recording ID",
                    *requestedID == recPtr->getID());
            return {std::move(rec), false};
        } else {
            // If no recording ID was specified, any existing recording means the current start
            // command should fail.
            uasserted(ErrorCodes::BadValue, "Traffic recording already active");
        }
    }

    *rec = _makeRecording(options, globalRecordingDirectory, svcCtx->getTickSource());
    return {std::move(rec), true};
}

void TrafficRecorder::_start(LockedRecordingHandle rec, ServiceContext* svcCtx) {
    std::shared_ptr<Recording> recording = *rec;

    uassert(ErrorCodes::BadValue, "Non-existent traffic recording cannot be started", recording);
    uassert(ErrorCodes::BadValue,
            "Traffic recording instance cannot be started repeatedly",
            !recording->isStarted());

    recording->start();
    _shouldRecord.store(true);

    // TODO SERVER-111903: Ensure all session starts are observed exactly once. A session
    // starting just before this getActiveSessions call may be reported twice.
    // For now, duplicate session starts are simpler to handle than omitted ones.
    auto sessions = getActiveSessions(svcCtx);
    // Record SessionStart events if any active sessions exist.
    for (const auto& [id, session] : sessions) {
        _observe(*recording, id, session, Message(), EventType::kSessionStart);
    }
}
void TrafficRecorder::_stop(LockedRecordingHandle handle, ServiceContext* svcCtx) {
    // Take the recording, if it exists.
    // Past this point, other operations cannot record events.
    std::shared_ptr<Recording> recording = std::move(*handle);

    uassert(ErrorCodes::BadValue, "Traffic recording not active", recording);

    // Record SessionEnd events if any active sessions exist.
    auto sessions = getActiveSessions(svcCtx);

    for (const auto& [id, session] : sessions) {
        _observe(*recording, id, session, Message(), EventType::kSessionEnd);
    }

    _shouldRecord.store(false);

    uassertStatusOK(recording->shutdown());
}

void TrafficRecorder::_fail() {
    _recording->reset();
}

std::shared_ptr<TrafficRecorder::Recording> TrafficRecorder::_getCurrentRecording() const {
    return *_recording;
}

class TrafficRecorder::TrafficRecorderSSS : public ServerStatusSection {
public:
    using ServerStatusSection::ServerStatusSection;

    bool includeByDefault() const override {
        return true;
    }

    BSONObj generateSection(OperationContext* opCtx,
                            const BSONElement& configElement) const override {
        auto& recorder = TrafficRecorder::get(opCtx->getServiceContext());

        if (!recorder._shouldRecord.load()) {
            return BSON("running" << false);
        }

        auto recording = recorder._getCurrentRecording();

        if (!recording) {
            return BSON("running" << false);
        }

        return recording->getStats();
    }
};
auto& trafficRecorderStats =
    *ServerStatusSectionBuilder<TrafficRecorder::TrafficRecorderSSS>("trafficRecording");

std::shared_ptr<TrafficRecorderForTest::RecordingForTest>
TrafficRecorderForTest::getCurrentRecording() const {
    return std::dynamic_pointer_cast<TrafficRecorderForTest::RecordingForTest>(
        _getCurrentRecording());
}


std::shared_ptr<TrafficRecorder::Recording> TrafficRecorderForTest::_makeRecording(
    const StartTrafficRecording& options,
    std::filesystem::path globalRecordingDirectory,
    TickSource* tickSource) const {
    return std::make_shared<TrafficRecorderForTest::RecordingForTest>(options, tickSource);
}

TrafficRecorderForTest::RecordingForTest::RecordingForTest(const StartTrafficRecording& options,
                                                           TickSource* tickSource)
    : TrafficRecorder::Recording(options, gTrafficRecordingDirectory, tickSource) {}

TrafficRecorderForTest::RecordingForTest::RecordingForTest(
    const StartTrafficRecording& options,
    std::filesystem::path globalRecordingDirectory,
    TickSource* tickSource)
    : TrafficRecorder::Recording(options, globalRecordingDirectory, tickSource) {}

MultiProducerSingleConsumerQueue<TrafficRecordingPacket,
                                 TrafficRecorder::Recording::CostFunction>::Pipe&
TrafficRecorderForTest::RecordingForTest::getPcqPipe() {
    return _pcqPipe;
}

void TrafficRecorderForTest::RecordingForTest::start() {
    // No-op for tests
}

Status TrafficRecorderForTest::RecordingForTest::shutdown() {
    // No-op for tests
    return Status::OK();
}

}  // namespace mongo
