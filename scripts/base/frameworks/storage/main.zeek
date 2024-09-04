##! The storage framework provides a way to store long-term
##! data to disk.

@load base/bif/storage.bif

module Storage;

export {
	## Options record for the built-in SQLite backend.
	type SqliteOptions: record {
		## Path to the database file on disk
		database_path: string;

		## Name of the table used for storing data
		table_name: string;

		## Key/value table for passing tuning parameters when opening
		## the database.  These must be pairs that can be passed to the
		## ``pragma`` command in sqlite.
		tuning_params: table[string] of string &default=table(
			["journal_mode"] = "WAL",
			["synchronous"] = "normal",
			["temp_store"] = "memory"
		);
	};

	## Opens a new backend connection based on a configuration object.
	##
	## btype: A tag indicating what type of backend should be opened.
	##
	## config: A record containing the configuration for the connection.
	##
	## Returns: A handle to the new backend connection.
	global open_backend: function(btype: Storage::Backend, config: any, key_type: any,
	                              val_type: any): opaque of Storage::BackendHandle;

	## Closes an existing backend connection.
	##
	## backend: A handle to a backend connection.
	##
	## Returns: A boolean indicating success or failure of the operation.
	global close_backend: function(backend: opaque of Storage::BackendHandle): bool;

	## Inserts a new entry into a backend.
	##
	## backend: A handle to a backend connection.
	##
	## key: A key value.
	##
	## value: A corresponding value.
	##
	## overwrite: A flag indicating whether this value should overwrite an existing entry
	## for the key.
	##
	## expire_time: An interval of time until the entry is automatically
	## removed from the backend.
	##
	## Returns: A boolean indicating success or failure of the operation.
	global put: function(backend: opaque of Storage::BackendHandle, key: any, value: any,
	                     overwrite: bool, expire_time: interval &default=0sec,
			     async_mode: bool &default=T): bool;

	## Gets an entry from the backend.
	##
	## backend: A handle to a backend connection.
	##
	## key: The key to look up.
	##
	## val_type: The type of the value to return.
	##
	## Returns: A boolean indicating success or failure of the
	## operation. Type conversion failures for the value will return false.
	global get: function(backend: opaque of Storage::BackendHandle, key: any,
			     async_mode: bool &default=T): any;

	## Erases an entry from the backend.
	##
	## backend: A handle to a backend connection.
	##
	## key: The key to erase.
	##
	## Returns: A boolean indicating success or failure of the operation.
	global erase: function(backend: opaque of Storage::BackendHandle, key: any,
			       async_mode: bool &default=T): bool;
}

function open_backend(btype: Storage::Backend, config: any, key_type: any, val_type: any): opaque of Storage::BackendHandle
{
	return Storage::__open_backend(btype, config, key_type, val_type);
}

function close_backend(backend: opaque of Storage::BackendHandle): bool
{
	return Storage::__close_backend(backend);
}

function put(backend: opaque of Storage::BackendHandle, key: any, value: any, overwrite: bool,
             expire_time: interval &default=0sec, async_mode: bool &default=T): bool
{
	return Storage::__put(backend, key, value, overwrite, expire_time, async_mode);
}

function get(backend: opaque of Storage::BackendHandle, key: any, async_mode: bool &default=T): any
{
	return Storage::__get(backend, key, async_mode);
}

function erase(backend: opaque of Storage::BackendHandle, key: any, async_mode: bool &default=T): bool
{
	return Storage::__erase(backend, key, async_mode);
}
