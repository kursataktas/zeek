# @TEST-DOC: Basic functionality for storage: opening/closing an sqlite backend, storing/retrieving/erasing basic data
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

@load base/frameworks/storage

# Create a typename here that can be passed down into open_backend.
type str: string;

event zeek_init() {
	# Create a database file in the .tmp directory with a 'testing' table
	local opts : Storage::SqliteOptions;
	opts$database_path = "test.sqlite";
	opts$table_name = "testing";

	local key = "key1111";
	local value = "value";

	# Test inserting/retrieving a key/value pair that we know won't be in
	# the backend yet.
	local b = Storage::open_backend(Storage::SQLITE, opts);
	local res = Storage::put(b, key, value, T);
	print res;

	local res2 = Storage::get(b, key, str);
	print res2;

	# Test overwriting a value with put()
	local value2 = "value2";
	local res3 = Storage::put(b, key, value2, T);
	print res3;

	local res4 = Storage::get(b, key, str);
	print res4;

	# Test erasing a key and getting a "false" result
	local res5 = Storage::erase(b, key);
	print res5;

	local res6 = Storage::get(b, key, str);
	if ( ! res6 as bool ) {
		print "got empty result";
	}

	# Insert something back into the database to test reopening
	Storage::put(b, key, value2, T);

	Storage::close_backend(b);

	# Test reopening the same backend and getting the data back out of it
	local b2 = Storage::open_backend(Storage::SQLITE, opts);
	local res7 = Storage::get(b2, key, str);
	print res7;
}
