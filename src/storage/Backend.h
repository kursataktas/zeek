// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/OpaqueVal.h"
#include "zeek/Val.h"

#include "nonstd/expected.hpp"

namespace zeek::storage {

// Result from storage operations that may return an error message. If the
// optional value is unset, the operation succeeded.
using ErrorResult = std::optional<std::string>;

// Result from storage operations that return Vals. The ValPtr is an
// IntrusivePtr to some result, and can be null if the operation failed. The
// string value will store an error message if the result is null.
using ValResult = nonstd::expected<ValPtr, std::string>;

namespace detail {
extern OpaqueTypePtr backend_opaque;
}

class Backend : public zeek::Obj {
public:
    Backend() = default;

    /**
     * Called by the manager system to open the backend.
     *
     * @param config A record type storing configuration options for the backend.
     * @return A result pair containing a bool with the success state, and a
     * possible error string if the operation failed.
     */
    ErrorResult Open(RecordValPtr config);

    /**
     * Finalizes the backend when it's being closed. Can be overridden by
     * derived classes.
     */
    virtual void Done() {}

    /**
     * Returns a descriptive tag representing the source for debugging.
     *
     * Must be overridden by derived classes.
     *
     * @return The debugging name.
     */
    virtual const char* Tag() = 0;

    /**
     * Store a new key/value pair in the backend.
     *
     * @param key the key for the pair
     * @param value the value for the pair
     * @param overwrite whether an existing value for a key should be overwritten.
     * @param expiration_time the time when this entry should be automatically
     * removed. Set to zero to disable expiration.
     * @return A result pair containing a bool with the success state, and a
     * possible error string if the operation failed.
     */
    ErrorResult Put(ValPtr key, ValPtr value, bool overwrite = true, double expiration_time = 0);

    /**
     * Retrieve a value from the backend for a provided key.
     *
     * @param key the key to lookup in the backend.
     * @param value_type The script-land type to be used when retrieving values
     * from the backend.
     * @return A result pair containing a ValPtr with the resulting value or
     * nullptr retrieval failed, and a string with the error message if the
     * operation failed.
     */
    ValResult Get(ValPtr key, TypePtr value_type);

    /**
     * Erases the value for a key from the backend.
     *
     * @return A result pair containing a bool with the success state, and a
     * possible error string if the operation failed.
     */
    ErrorResult Erase(ValPtr key);

    /**
     * Returns whether the backend is opened.
     */
    virtual bool IsOpen() = 0;

protected:
    /**
     * The workhorse method for Open().
     */
    virtual ErrorResult DoOpen(RecordValPtr config) = 0;

    /**
     * The workhorse method for Put().
     */
    virtual ErrorResult DoPut(ValPtr key, ValPtr value, bool overwrite = true, double expiration_time = 0) = 0;

    /**
     * The workhorse method for Get().
     */
    virtual ValResult DoGet(ValPtr key, TypePtr value_type) = 0;

    /**
     * The workhorse method for Erase().
     */
    virtual ErrorResult DoErase(ValPtr key) = 0;
};

using BackendPtr = zeek::IntrusivePtr<Backend>;

class BackendHandleVal : public OpaqueVal {
public:
    BackendHandleVal() : OpaqueVal(detail::backend_opaque) {}
    BackendHandleVal(BackendPtr backend) : OpaqueVal(detail::backend_opaque), backend(std::move(backend)) {}

    ~BackendHandleVal() override = default;

    void ValDescribe(ODesc* d) const override {}

    const char* OpaqueName() const override { return "BackendHandleVal"; }

    BackendPtr backend;
};

// Result from calls to open a new backend. The value will be set if the open
// operation succeeded, and the string value is an error message if the
// operation failed. This isn't used by the backends themselves, but by the
// Manager to return error messages to callers if necessary (notably BIFs).
using BackendResult = nonstd::expected<BackendPtr, std::string>;

} // namespace zeek::storage
