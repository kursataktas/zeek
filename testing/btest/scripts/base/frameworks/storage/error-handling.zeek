# @TEST-DOC: Tests various error handling scenarios for the storage framework
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

@load base/frameworks/storage
@load base/frameworks/reporter

# Create a typename here that can be passed down into open_backend.
type str: string;

event zeek_init() {
	# Test opening a database with an invalid path
	local opts : Storage::SqliteOptions;
	opts$database_path = "/this/path/should/not/exist/test.sqlite";
	opts$table_name = "testing";

	# This should report an error in .stderr and reporter.log
	local b = Storage::open_backend(Storage::SQLITE, opts);

	# Open a valid database file and then close it
	opts$database_path = "test.sqlite";
	b = Storage::open_backend(Storage::SQLITE, opts);
	Storage::close_backend(b);

	# Attempt to use closed handle
	Storage::put(b, "a", "b", F);
}
