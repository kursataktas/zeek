// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/Manager.h"

namespace zeek::storage {

Manager::Manager() : plugin::ComponentManager<storage::Component>("Storage", "Backend") {}

void Manager::InitPostScript() { detail::backend_opaque = make_intrusive<OpaqueType>("Storage::Backend"); }

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

    return IntrusivePtr<Backend>{AdoptRef{}, b};
}

void Manager::CloseBackend(BackendPtr backend) { backend->Done(); }

} // namespace zeek::storage
