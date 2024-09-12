// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <condition_variable>
#include <mutex>

#include "zeek/iosource/IOSource.h"
#include "zeek/storage/Backend.h"

// Forward declare some types from hiredis to avoid including the header here
struct redisAsyncContext;
struct redisReply;

namespace zeek::storage::backends::redis {

class RedisAsync : public Backend, public zeek::iosource::IOSource {
public:
    RedisAsync() : Backend(true), IOSource(true) {}
    ~RedisAsync() override = default;

    static Backend* Instantiate();

    /**
     * Returns a descriptive tag representing the source for debugging.
     *
     * @return The debugging name.
     */
    const char* Tag() override { return "RedisStorage"; }

    /**
     * Called by the manager system to open the backend.
     */
    ErrorResult DoOpen(RecordValPtr config) override;

    /**
     * Finalizes the backend when it's being closed.
     */
    void Done() override;

    /**
     * Returns whether the backend is opened.
     */
    bool IsOpen() override {
        // This can't just check the context because we might be in an in-between
        // state where the context is valid but we're not actually connected.
        return connected;
    }

    /**
     * The workhorse method for Retrieve().
     */
    ErrorResult DoPut(ValPtr key, ValPtr value, bool overwrite = true, double expiration_time = 0,
                      ErrorResultCallback* cb = nullptr) override;

    /**
     * The workhorse method for Get().
     */
    ValResult DoGet(ValPtr key, ValResultCallback* cb = nullptr) override;

    /**
     * The workhorse method for Erase().
     */
    ErrorResult DoErase(ValPtr key, ErrorResultCallback* cb = nullptr) override;

    // IOSource interface
    double GetNextTimeout() override { return -1; }
    void Process() override {}
    void ProcessFd(int fd, int flags) override;

    // Hiredis async interface
    void OnConnect(int status);
    void OnDisconnect(int status);
    void OnAddRead();
    void OnDelRead();
    void OnAddWrite();
    void OnDelWrite();
    void OnCleanup();

    void HandlePutResult(uint64_t index, redisReply* reply, ErrorResultCallback* callback);
    void HandleGetResult(uint64_t index, redisReply* reply, ValResultCallback* callback);
    void HandleEraseResult(uint64_t index, redisReply* reply, ErrorResultCallback* callback);

    struct OpData {
        uint64_t index;
        RedisAsync* backend;
        void* callback;
    };

private:
    void OnPut(redisAsyncContext* ctx, void* reply, void* privdata);

    ErrorResult checkError(int code);

    redisAsyncContext* ctx = nullptr;
    bool connected = false;

    // Options passed in the record from script land
    std::string server_addr;
    std::string key_prefix;
    std::chrono::microseconds op_timeout;

    int readFd = -1;
    int writeFd = -1;

    uint64_t op_index = 0;
    std::map<uint64_t, std::variant<ValResult, ErrorResult>> op_results;

    std::condition_variable sync_cv;
    std::mutex sync_cv_mtx;

    uint64_t op_req_index = 0;
    uint64_t op_resp_index = 0;
};

} // namespace zeek::storage::backends::redis
