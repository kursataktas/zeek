// See the file "COPYING" in the main distribution directory for copyright.

#include "Redis.h"

#include "zeek/Func.h"
#include "zeek/Val.h"

#include "hiredis/hiredis.h"

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

    ctx = redisConnectWithOptions(&opt);
    if ( ctx == nullptr || ctx->err ) {
        if ( ctx )
            return util::fmt("Failed to open connection to Redis server at %s", server_addr.c_str());
        else
            return util::fmt("Failed to open connection to Redis server at %s: %s", server_addr.c_str(), ctx->errstr);
    }

    key_prefix = config->GetField<StringVal>("key_prefix")->ToStdString();

    // TODO: register file descriptor with iosource_mgr for async mode

    return std::nullopt;
}

/**
 * Finalizes the backend when it's being closed.
 */
void Redis::Done() {
    if ( ctx ) {
        redisFree(ctx);
        ctx = nullptr;
    }
}

/**
 * The workhorse method for Put(). This must be implemented by plugins.
 */
ErrorResult Redis::DoPut(ValPtr key, ValPtr value, bool overwrite, double expiration_time, ErrorResultCallback* cb) {
    if ( ! ctx )
        return "Connection is not open";

    auto json_key = util::strreplace(key->ToJSON()->ToStdString(), "\"", "\\\"");
    auto json_value = util::strreplace(value->ToJSON()->ToStdString(), "\"", "\\\"");

    std::string args = util::fmt("SET %s:\"%s\" \"%s\"", key_prefix.data(), json_key.data(), json_value.data());

    if ( ! overwrite )
        args.append(" NX");

    if ( expiration_time > 0.0 )
        args.append(util::fmt("PXAT %lld", static_cast<uint64_t>(expiration_time * 1e6)));

    redisReply* reply = (redisReply*)redisCommand(ctx, args.c_str());

    if ( ! reply )
        return util::fmt("Put operation failed: %s", ctx->errstr);

    freeReplyObject(reply);

    return std::nullopt;
}

/**
 * The workhorse method for Get(). This must be implemented for plugins.
 */
ValResult Redis::DoGet(ValPtr key, ValResultCallback* cb) {
    if ( ! ctx )
        return nonstd::unexpected<std::string>("Connection is not open");

    auto json_key = util::strreplace(key->ToJSON()->ToStdString(), "\"", "\\\"");
    std::string args = util::fmt("GET %s:\"%s\"", key_prefix.data(), json_key.data());

    redisReply* reply = (redisReply*)redisCommand(ctx, args.c_str());

    if ( ! reply )
        return nonstd::unexpected<std::string>(util::fmt("Get operation failed: %s", ctx->errstr));

    // TODO: unescape quotes
    std::string reply_str{reply->str};
    reply_str = util::strreplace(reply_str, "\\\"", "\"");
    reply_str.erase(0, 1);
    reply_str.erase(reply_str.size() - 1, 1);

    auto val = zeek::detail::ValFromJSON(reply->str, val_type, Func::nil);
    freeReplyObject(reply);

    if ( std::holds_alternative<ValPtr>(val) ) {
        ValPtr val_v = std::get<ValPtr>(val);
        return val_v;
    }
    else {
        return nonstd::unexpected<std::string>(std::get<std::string>(val));
    }

    return nonstd::unexpected<std::string>("DoGet not implemented");
}

/**
 * The workhorse method for Erase(). This must be implemented for plugins.
 */
ErrorResult Redis::DoErase(ValPtr key, ErrorResultCallback* cb) {
    if ( ! ctx )
        return "Connection is not open";

    auto json_key = key->ToJSON();

    std::string args = util::fmt("DEL %s:\"%s\"", key_prefix.data(), json_key->ToStdStringView().data());

    redisReply* reply = (redisReply*)redisCommand(ctx, args.c_str());

    if ( ! reply )
        return util::fmt("Put operation failed: %s", ctx->errstr);

    freeReplyObject(reply);

    return std::nullopt;
}

} // namespace zeek::storage::backends::redis
