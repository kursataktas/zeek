// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/Manager.h"

namespace zeek::storage {

void detail::ExpireTimer::Dispatch(double t, bool is_expire) {
    if ( is_expire )
        return;

    storage_mgr->Expire();
    storage_mgr->StartExpireTimer();
}


Manager::Manager() : plugin::ComponentManager<storage::Component>("Storage", "Backend") {}

void Manager::InitPostScript() {
    detail::backend_opaque = make_intrusive<OpaqueType>("Storage::Backend");
    StartExpireTimer();
}

BackendResult Manager::OpenBackend(const Tag& type, RecordValPtr config) {
    Component* c = Lookup(type);
    if ( ! c ) {
        return nonstd::unexpected<std::string>(
            util::fmt("Request to open unknown backend (%d:%d)", type.Type(), type.Subtype()));
    }

    if ( ! c->Factory() ) {
        return nonstd::unexpected<std::string>(
            util::fmt("Factory invalid for backend %s", GetComponentName(type).c_str()));
    }

    Backend* b = c->Factory()();

    if ( ! b ) {
        return nonstd::unexpected<std::string>(
            util::fmt("Failed to instantiate backend %s", GetComponentName(type).c_str()));
    }

    if ( auto res = b->Open(std::move(config)); res.has_value() ) {
        delete b;
        return nonstd::unexpected<std::string>(
            util::fmt("Failed to open backend %s: %s", GetComponentName(type).c_str(), res.value().c_str()));
    }

    // TODO: post storage_connection_established event

    BackendPtr bp = IntrusivePtr<Backend>{AdoptRef{}, b};

    {
        std::unique_lock<std::mutex> lk;
        backends.push_back(bp);
    }

    return bp;
}

void Manager::CloseBackend(BackendPtr backend) {
    {
        std::unique_lock<std::mutex> lk;
        auto it = std::find(backends.begin(), backends.end(), backend);
        if ( it == backends.end() )
            return;

        backends.erase(it);
    }
    backend->Done();

    // TODO: post storage_connection_lost event
}

void Manager::Expire() {
    DBG_LOG(DBG_STORAGE, "Expire running, have %zu backends to check", backends.size());
    std::unique_lock<std::mutex> lk;
    for ( const auto& b : backends )
        b->Expire();
}

void Manager::StartExpireTimer() {
    zeek::detail::timer_mgr->Add(new detail::ExpireTimer(run_state::network_time + BifConst::Storage::expire_interval));
}


} // namespace zeek::storage
