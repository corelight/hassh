module SSH;

redef record SSH::Info += {
	# The version is just in case the method changes in the future,
	# as it may be handy to reference the version historically.
	hasshVersion: string &log &default="1.0";

	# Client/server hashes.
	hassh: string &log &optional;
	hasshServer: string &log &optional;

	# Server host key as seen by a client.
	cshka: string &log &optional;

	# The algorithms that went into the client hash.
	hasshAlgorithms: string &log &optional;

	# Server host key as seen by a server.
	sshka: string &log &optional;

	# The algorithms that went into the server hash.
	hasshServer_Algorithms: string &log &optional;
};

option log_raw_hassh_algorithms = T;
option log_key_algorithm = T;

# Takes key exchange, encryption, mac, and compression algorithm vectors and
# returns the corresponding algorithm list.
function extract_algo_list(kex: string_vec, enc: string_vec, mac: string_vec,
			   cmp: string_vec) : string
	{
	local kex_list = join_string_vec(kex, ",");
	local enc_list = join_string_vec(enc, ",");
	local mac_list = join_string_vec(mac, ",");
	local cmp_list = join_string_vec(cmp, ",");

	return kex_list + ";" + enc_list + ";" + mac_list + ";" + cmp_list;
	}

# Build client fingerprint.
function get_hassh(c: connection, capabilities: SSH::Capabilities)
	{
	local algo_list = extract_algo_list(
			capabilities$kex_algorithms,
			capabilities$encryption_algorithms$client_to_server,
			capabilities$mac_algorithms$client_to_server,
			capabilities$compression_algorithms$client_to_server);

	c$ssh$hassh = md5_hash(algo_list);

	if ( log_raw_hassh_algorithms )
		c$ssh$hasshAlgorithms = algo_list;

	if ( log_key_algorithm )
		c$ssh$cshka = join_string_vec(capabilities$server_host_key_algorithms, ",");
	}

# Build server fingerprint.
function get_hasshServer(c: connection, capabilities: SSH::Capabilities)
	{
	local algo_list = extract_algo_list(
			capabilities$kex_algorithms,
			capabilities$encryption_algorithms$server_to_client,
			capabilities$mac_algorithms$server_to_client,
			capabilities$compression_algorithms$server_to_client);

	c$ssh$hasshServer = md5_hash(algo_list);

	if ( log_raw_hassh_algorithms )
		c$ssh$hasshServer_Algorithms = algo_list;

	if ( log_key_algorithm )
		c$ssh$sshka = join_string_vec(capabilities$server_host_key_algorithms, ",");
	}

event ssh_capabilities(c: connection, cookie: string,
		       capabilities: SSH::Capabilities)
	{
	# This should really never apply, but just in case.
	if ( ! c?$ssh )
		return;

	if ( capabilities$is_server && ! c$ssh?$hasshServer )
		get_hasshServer(c, capabilities);

	else if ( ! capabilities$is_server && ! c$ssh?$hassh )
		get_hassh(c, capabilities);
	}
