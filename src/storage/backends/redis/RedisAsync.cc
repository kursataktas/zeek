// See the file "COPYING" in the main distribution directory for copyright.

#include "Redis.h"

#include "zeek/Func.h"
#include "zeek/RunState.h"
#include "zeek/Val.h"
#include "zeek/iosource/Manager.h"

#include "hiredis/async.h"
#include "hiredis/hiredis.h"

static void redisOnConnect(const redisAsyncContext* c, int status) {
    printf("on connect\n");
    auto backend = static_cast<zeek::storage::backends::redis::Redis*>(c->data);
    backend->OnConnect(status);
}

static void redisOnDisconnect(const redisAsyncContext* c, int status) {
    auto backend = static_cast<zeek::storage::backends::redis::Redis*>(c->data);
    backend->OnDisconnect(status);
}

static void redisAddRead(void* data) {
    auto backend = static_cast<zeek::storage::backends::redis::Redis*>(data);
    backend->OnAddRead();
}

static void redisDelRead(void* data) {
    auto backend = static_cast<zeek::storage::backends::redis::Redis*>(data);
    backend->OnDelRead();
}

static void redisAddWrite(void* data) {
    auto backend = static_cast<zeek::storage::backends::redis::Redis*>(data);
    backend->OnAddWrite();
}

static void redisDelWrite(void* data) {
    auto backend = static_cast<zeek::storage::backends::redis::Redis*>(data);
    backend->OnDelWrite();
}

static void redisCleanup(void* data) {
    auto backend = static_cast<zeek::storage::backends::redis::Redis*>(data);
    backend->OnCleanup();
}

namespace zeek::storage::backends::redis {
storage::Backend* Redis::Instantiate() { return new Redis(); }

/**
 * Called by the manager system to open the backend.
 *
 * Derived classes must implement this method. If successful, the
 * implementation must call \a Opened(); if not, it must call Error()
 * with a corresponding message.
 */
ErrorResult Redis::DoOpen(RecordValPtr config) {
    std::unique_lock<std::mutex> lk(sync_cv_mtx);

    redisOptions opt = {0};

    StringValPtr address = config->GetField<StringVal>("server_addr");
    if ( address ) {
        PortValPtr port = config->GetField<PortVal>("server_port");
        server_addr = util::fmt("%s:%d", address->ToStdStringView().data(), port->Port());
        REDIS_OPTIONS_SET_TCP(&opt, address->ToStdStringView().data(), port->Port());
    }
    else {
        StringValPtr unix_sock = config->GetField<StringVal>("server_unix_socket");
        server_addr = address->ToStdString();
        REDIS_OPTIONS_SET_UNIX(&opt, unix_sock->ToStdStringView().data());
    }

    opt.options |= REDIS_OPT_PREFER_IPV4;
    // TODO: do REDIS_OPT_NOAUTOFREE or REDIS_OPT_NOAUTOFREEREPLIES need to be set? Does that
    // affect local data or the remote side?

    struct timeval timeout = {5, 0};
    opt.connect_timeout = &timeout;

    ctx = redisAsyncConnect("localhost", 6379);
    //    ctx = redisAsyncConnectWithOptions(&opt);
    if ( ctx == nullptr || ctx->err ) {
        std::string errmsg = util::fmt("Failed to open connection to Redis server at %s", server_addr.c_str());

        if ( ctx ) {
            errmsg.append(": ");
            errmsg.append(ctx->errstr);
        }

        redisAsyncFree(ctx);
        ctx = nullptr;
        return errmsg;
    }

    ctx->data = this;

    redisAsyncSetConnectCallback(ctx, redisOnConnect);
    redisAsyncSetDisconnectCallback(ctx, redisOnDisconnect);

    key_prefix = config->GetField<StringVal>("key_prefix")->ToStdString();
    op_timeout = std::chrono::microseconds(static_cast<long>(config->GetField<IntervalVal>("op_timeout")->Get() * 1e6));

    // Block here until the connection is successful or we timeout
    printf("waiting for connection\n");
    if ( auto res = sync_cv.wait_for(lk, op_timeout); res == std::cv_status::timeout ) {
        std::string errmsg =
            util::fmt("Failed to open connection to Redis server at %s: timed out", server_addr.c_str());
        redisAsyncFree(ctx);
        connected = false;
        ctx = nullptr;
        return errmsg;
    }

    ctx->ev.data = this;
    ctx->ev.addRead = redisAddRead;
    ctx->ev.delRead = redisDelRead;
    ctx->ev.addWrite = redisAddWrite;
    ctx->ev.delWrite = redisDelWrite;
    ctx->ev.cleanup = redisCleanup;

    return std::nullopt;
}

void Redis::OnConnect(int status) {
    printf("OnConnect status = %d\n", status);

    if ( status == REDIS_OK ) {
        connected = true;
        sync_cv.notify_all();
        return;
    }

    // TODO: we could attempt to reconnect here
}

/**
 * Finalizes the backend when it's being closed.
 */
void Redis::Done() {
    std::unique_lock<std::mutex> lk(sync_cv_mtx);

    if ( ctx ) {
        redisAsyncDisconnect(ctx);

        // Block here until the connection is successful or we timeout. We don't care about the result
        // since we're disconnecting anyways.
        sync_cv.wait_for(lk, op_timeout);

        redisAsyncFree(ctx);
        ctx = nullptr;
        connected = false;
    }
}

void Redis::OnDisconnect(int status) {
    if ( status == REDIS_OK ) {
        // TODO: this was an intentional disconnect, nothing to do?
    }
    else {
        // TODO: this was unintentional, should we reconnect?
    }

    connected = false;
    sync_cv.notify_all();
}

static void redisPut(redisAsyncContext* ctx, void* reply, void* privdata) {
    Redis::OpData* opdata = static_cast<Redis::OpData*>(privdata);
    opdata->backend->HandlePutResult(opdata->index, static_cast<redisReply*>(reply),
                                     static_cast<ErrorResultCallback*>(opdata->callback));
    delete opdata;
}

/**
 * The workhorse method for Put(). This must be implemented by plugins.
 */
ErrorResult Redis::DoPut(ValPtr key, ValPtr value, bool overwrite, double expiration_time, ErrorResultCallback* cb) {
    if ( ! ctx )
        return "Connection is not open";

    std::unique_lock<std::mutex> lk(sync_cv_mtx);

    std::string format = "SET %s:%s %s PXAT %d";
    if ( ! overwrite )
        format.append(" NX");
    if ( expiration_time > 0.0 )
        format.append(" PXAT %d");

    auto json_key = key->ToJSON()->ToStdString();
    auto json_value = value->ToJSON()->ToStdString();

    OpData* data = new OpData{++op_index, this, cb};
    int status;
    if ( expiration_time > 0.0 )
        status = redisAsyncCommand(ctx, redisPut, data, format.c_str(), key_prefix.data(), json_key.data(),
                                   json_value.data(), static_cast<uint64_t>(expiration_time * 1e6));
    else
        status = redisAsyncCommand(ctx, redisPut, data, format.c_str(), key_prefix.data(), json_key.data(),
                                   json_value.data());

    if ( connected && status == REDIS_ERR )
        return util::fmt("Put operation failed: %s", ctx->errstr);

    // If in sync mode, block here until the operation finishes
    if ( ! cb ) {
        ++op_req_index;
        uint64_t expected_idx = op_req_index;
        bool res = sync_cv.wait_for(lk, op_timeout, [expected_idx, this]() {
            return this->op_resp_index >= expected_idx || zeek::run_state::terminating;
        });

        if ( ! res )
            return "Timeout waiting for put operation";

        ErrorResult er = std::get<ErrorResult>(op_results[op_index]);
        return er;
    }

    return std::nullopt;
}

void Redis::HandlePutResult(uint64_t index, redisReply* reply, ErrorResultCallback* callback) {
    ErrorResult res;
    if ( reply->type == REDIS_REPLY_ERROR )
        res = util::fmt("Put operation failed: %s", reply->str);

    freeReplyObject(reply);

    if ( callback ) {
        callback->Complete(res);
    }
    else {
        std::unique_lock<std::mutex> lk(sync_cv_mtx);
        op_resp_index = op_req_index;
        op_results.insert({index, res});
        sync_cv.notify_all();
    }
}

static void redisGet(redisAsyncContext* ctx, void* reply, void* privdata) {
    Redis::OpData* opdata = static_cast<Redis::OpData*>(privdata);
    opdata->backend->HandleGetResult(opdata->index, static_cast<redisReply*>(reply),
                                     static_cast<ValResultCallback*>(opdata->callback));
    delete opdata;
}

/**
 * The workhorse method for Get(). This must be implemented for plugins.
 */
ValResult Redis::DoGet(ValPtr key, ValResultCallback* cb) {
    if ( ! ctx )
        return nonstd::unexpected<std::string>("Connection is not open");

    std::unique_lock<std::mutex> lk(sync_cv_mtx);

    OpData* data = new OpData{++op_index, this, cb};
    int status =
        redisAsyncCommand(ctx, redisGet, data, "GET %s:%s", key_prefix.data(), key->ToJSON()->ToStdStringView().data());

    if ( connected && status == REDIS_ERR )
        return nonstd::unexpected<std::string>(util::fmt("Get operation failed: %s", ctx->errstr));

    // If in sync mode, block here until the operation finishes
    if ( ! cb ) {
        ++op_req_index;
        uint64_t expected_idx = op_req_index;
        bool res = sync_cv.wait_for(lk, op_timeout, [expected_idx, this]() {
            return this->op_resp_index >= expected_idx || zeek::run_state::terminating;
        });

        if ( ! res )
            return nonstd::unexpected<std::string>("Timeout waiting for get operation");

        ValResult vr = std::get<ValResult>(op_results[op_index]);
        return vr;
    }

    return nonstd::unexpected<std::string>("Async get operation completed successfully");
}

void Redis::HandleGetResult(uint64_t index, redisReply* reply, ValResultCallback* callback) {
    auto val = zeek::detail::ValFromJSON(reply->str, val_type, Func::nil);
    freeReplyObject(reply);

    ValResult res;
    if ( std::holds_alternative<ValPtr>(val) ) {
        ValPtr val_v = std::get<ValPtr>(val);
        res = val_v;
    }

    if ( ! res )
        res = nonstd::unexpected<std::string>(std::get<std::string>(val));

    if ( callback ) {
        callback->Complete(res);
    }
    else {
        std::unique_lock<std::mutex> lk(sync_cv_mtx);
        op_resp_index = op_req_index;
        op_results.insert({index, res});
        sync_cv.notify_all();
    }
}

static void redisErase(redisAsyncContext* ctx, void* reply, void* privdata) {
    Redis::OpData* opdata = static_cast<Redis::OpData*>(privdata);
    opdata->backend->HandleEraseResult(opdata->index, static_cast<redisReply*>(reply),
                                       static_cast<ErrorResultCallback*>(opdata->callback));
    delete opdata;
}

/**
 * The workhorse method for Erase(). This must be implemented for plugins.
 */
ErrorResult Redis::DoErase(ValPtr key, ErrorResultCallback* cb) {
    if ( ! ctx )
        return "Connection is not open";

    std::unique_lock<std::mutex> lk(sync_cv_mtx);

    auto json_key = key->ToJSON();

    std::string args = util::fmt("DEL %s:\"%s\"", key_prefix.data(), json_key->ToStdStringView().data());
    OpData* data = new OpData{++op_index, this, cb};

    int status =
        redisAsyncCommand(ctx, redisErase, data, "DEL %s:%s", key_prefix.data(), json_key->ToStdStringView().data());

    if ( connected && status == REDIS_ERR )
        return util::fmt("Erase operation failed: %s", ctx->errstr);

    // If in sync mode, block here until the operation finishes
    if ( ! cb ) {
        ++op_req_index;
        uint64_t expected_idx = op_req_index;
        bool res = sync_cv.wait_for(lk, op_timeout, [expected_idx, this]() {
            return this->op_resp_index >= expected_idx || zeek::run_state::terminating;
        });

        if ( ! res )
            return "Timeout waiting for erase operation";

        ErrorResult er = std::get<ErrorResult>(op_results[op_index]);
        return er;
    }

    return std::nullopt;
}

void Redis::HandleEraseResult(uint64_t index, redisReply* reply, ErrorResultCallback* callback) {
    ErrorResult res;
    if ( reply->type == REDIS_REPLY_ERROR )
        res = util::fmt("Erase operation failed: %s", reply->str);

    freeReplyObject(reply);

    if ( callback ) {
        callback->Complete(res);
    }
    else {
        std::unique_lock<std::mutex> lk(sync_cv_mtx);
        op_resp_index = op_req_index;
        op_results.insert({index, res});
        sync_cv.notify_all();
    }
}

void Redis::ProcessFd(int fd, int flags) {
    printf("processfd\n");
    if ( fd == readFd )
        redisAsyncHandleRead(ctx);
    else if ( fd == writeFd )
        redisAsyncHandleWrite(ctx);
}

void Redis::OnAddRead() {
    if ( readFd != -1 )
        // TODO: probably should log something here
        return;

    readFd = ctx->c.fd;
    iosource_mgr->RegisterFd(readFd, this, IOSource::READ);
}

void Redis::OnDelRead() {
    if ( readFd == -1 )
        return;

    iosource_mgr->UnregisterFd(readFd, this);
    readFd = -1;
}

void Redis::OnAddWrite() {
    printf("add write %d\n", ctx->c.fd);
    if ( writeFd != -1 )
        // TODO: probably should log something here
        return;

    writeFd = ctx->c.fd;
    iosource_mgr->RegisterFd(writeFd, this, IOSource::WRITE);
}

void Redis::OnDelWrite() {
    printf("del write %d %d\n", ctx->c.fd, writeFd);
    if ( writeFd == -1 )
        return;

    iosource_mgr->UnregisterFd(writeFd, this);
    writeFd = -1;
}

void Redis::OnCleanup() {
    OnDelRead();
    OnDelWrite();
}

} // namespace zeek::storage::backends::redis
