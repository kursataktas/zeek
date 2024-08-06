// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/plugin/ComponentManager.h"
#include "zeek/storage/Backend.h"
#include "zeek/storage/Component.h"

namespace zeek::storage {

class Manager final : public plugin::ComponentManager<Component> {
public:
    Manager();
    ~Manager() = default;

    /**
     * Initialization of the manager. This is called late during Zeek's
     * initialization after any scripts are processed.
     */
    void InitPostScript();

    /**
     * Opens a new storage backend.
     *
     * @param type The tag for the type of backend being opened.
     * @param config A record val representing the configuration for this
     * type of backend.
     * @return A pointer to a backend instance.
     */
    BackendPtr OpenBackend(const Tag& type, RecordValPtr configuration);

    // TODO
    // - Does the manager really need to do anything except provide a method for opening
    //   new backends? The backends have store/retrieve methods of their own, so scripts/BIFs
    //   can just call those directly if they have the handle. Users of the backends (tables,
    //   etc) can close the backends themselves instead of asking the manager to.

    /**
     * Closes a storage backend.
     */
    void CloseBackend(BackendPtr backend);

    // TODO:
    // - Hooks for storage-backed tables?
    // - Handling aggregation from workers on a single manager?
};

} // namespace zeek::storage

namespace zeek {

extern storage::Manager* storage_mgr;

} // namespace zeek
