// See the file "COPYING" in the main distribution directory for copyright.

#include "Backend.h"

#include "zeek/Trigger.h"
#include "zeek/broker/Data.h"

namespace zeek::storage {

ErrorResultCallback::ErrorResultCallback(zeek::detail::trigger::Trigger* trigger, const void* assoc) : assoc(assoc) {
    Ref(trigger);
    this->trigger = trigger;
}
ErrorResultCallback::~ErrorResultCallback() { Unref(trigger); }

void ErrorResultCallback::Complete(const ErrorResult& res) {
    zeek::Val* result;

    if ( res )
        result = new StringVal(res.value());
    else
        result = val_mgr->Bool(true).get();

    trigger->Cache(assoc, result);
    Unref(result);
    trigger->Release();
}

void ErrorResultCallback::Timeout() {
    auto v = new StringVal("Timeout during request");
    trigger->Cache(assoc, v);
    Unref(v);
}

ValResultCallback::ValResultCallback(zeek::detail::trigger::Trigger* trigger, const void* assoc) : assoc(assoc) {
    Ref(trigger);
    this->trigger = trigger;
}
ValResultCallback::~ValResultCallback() { Unref(trigger); }

void ValResultCallback::Complete(const ValResult& res) {
    zeek::Val* result;

    if ( res ) {
        result = res.value().get();
        Ref(result);
    }
    else
        result = new StringVal(res.error());

    trigger->Cache(assoc, result);
    Unref(result);
    trigger->Release();
}

void ValResultCallback::Timeout() {
    auto v = new StringVal("Timeout during request");
    trigger->Cache(assoc, v);
    Unref(v);
}

ErrorResult Backend::Open(RecordValPtr config) { return DoOpen(std::move(config)); }

ErrorResult Backend::Put(ValPtr key, ValPtr value, bool overwrite, double expiration_time, ErrorResultCallback* cb) {
    // The intention for this method is to do some other heavy lifting in regard
    // to backends that need to pass data through the manager instead of directly
    // through the workers. For the first versions of the storage framework it
    // just calls the backend itself directly.
    auto res = DoPut(std::move(key), std::move(value), overwrite, expiration_time, cb);

    if ( ! native_async && cb )
        cb->Complete(res);

    return res;
}

ValResult Backend::Get(ValPtr key, TypePtr value_type, ValResultCallback* cb) {
    // See the note in Put().
    auto res = DoGet(std::move(key), std::move(value_type), cb);

    if ( ! native_async && cb )
        cb->Complete(res);

    return res;
}

ErrorResult Backend::Erase(ValPtr key, ErrorResultCallback* cb) {
    // See the note in Put().
    auto res = DoErase(std::move(key), cb);

    if ( ! native_async && cb )
        cb->Complete(res);

    return res;
}

zeek::OpaqueTypePtr detail::backend_opaque;
IMPLEMENT_OPAQUE_VALUE(detail::BackendHandleVal)

std::optional<BrokerData> detail::BackendHandleVal::DoSerializeData() const {
    // Cannot serialize.
    return std::nullopt;
}

bool detail::BackendHandleVal::DoUnserializeData(BrokerDataView) {
    // Cannot unserialize.
    return false;
}

} // namespace zeek::storage
