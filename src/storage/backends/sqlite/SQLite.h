// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/3rdparty/sqlite3.h"
#include "zeek/storage/Backend.h"

namespace zeek::storage::backends::sqlite {

class SQLite : public Backend {
public:
    SQLite() : Backend(false) {}
    ~SQLite() override = default;

    static Backend* Instantiate();

    /**
     * Returns a descriptive tag representing the source for debugging.
     *
     * @return The debugging name.
     */
    const char* Tag() override { return "SQLiteStorage"; }

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
    bool IsOpen() override { return db != nullptr; }

    /**
     * The workhorse method for Retrieve().
     */
    ErrorResult DoPut(ValPtr key, ValPtr value, bool overwrite = true, double expiration_time = 0,
                      ErrorResultCallback* cb = nullptr) override;

    /**
     * The workhorse method for Get().
     */
    ValResult DoGet(ValPtr key, TypePtr value_type, ValResultCallback* cb = nullptr) override;

    /**
     * The workhorse method for Erase().
     */
    ErrorResult DoErase(ValPtr key, ErrorResultCallback* cb = nullptr) override;

    void Expire() override;

private:
    ErrorResult checkError(int code);

    sqlite3* db = nullptr;
    std::unordered_map<std::string, sqlite3_stmt*> prepared_stmts;

    std::string full_path;
    std::string table_name;
};

} // namespace zeek::storage::backends::sqlite
