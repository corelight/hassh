module SSH;

redef record SSH::Info += {
	# The version is just in case the method changes in the future,
	# as it may be handy to reference the version historically.
	hasshVersion: string &log &default="1.0";
	hassh: string &log &optional;
	hasshServer: string &log &optional;
	cshka: string &log &optional;
	hasshAlgorithms: string &log &optional;
	sshka: string &log &optional;
	hasshServer_Algorithms: string &log &optional;
};

option log_raw_hasshAlgorithms = T;
option log_key_algorithm = T;

# Build Client fingerprint
function get_hassh(c: connection, capabilities: SSH::Capabilities)
	{
	local ckex = join_string_vec(capabilities$kex_algorithms, ",");
	local ceacts = join_string_vec(
	    capabilities$encryption_algorithms$client_to_server, ",");
	local cmacts = join_string_vec(capabilities$mac_algorithms$client_to_server,
	    ",");
	local ccacts = join_string_vec(
	    capabilities$compression_algorithms$client_to_server, ",");

	# Concatenate the four selected lists of algorithms.
	local hasshAlgorithms = string_cat(ckex, ";", ceacts, ";", cmacts, ";",
	    ccacts);
	c$ssh$hassh = md5_hash(hasshAlgorithms);

	if ( log_raw_hasshAlgorithms )
		c$ssh$hasshAlgorithms = hasshAlgorithms;
	if ( log_key_algorithm )
		c$ssh$cshka = join_string_vec(capabilities$server_host_key_algorithms, ",");
	}

# Build Server fingerprint
function get_hasshServer(c: connection, capabilities: SSH::Capabilities)
	{
	local skex = join_string_vec(capabilities$kex_algorithms, ",");
	local seastc = join_string_vec(
	    capabilities$encryption_algorithms$server_to_client, ",");
	local smastc = join_string_vec(capabilities$mac_algorithms$server_to_client,
	    ",");
	local scastc = join_string_vec(
	    capabilities$compression_algorithms$server_to_client, ",");

	# Concatenate the four selected lists of algorithms.
	local hasshServer_Algorithms = string_cat(skex, ";", seastc, ";", smastc, ";",
	    scastc);
	c$ssh$hasshServer = md5_hash(hasshServer_Algorithms);

	if ( log_raw_hasshAlgorithms )
		c$ssh$hasshServer_Algorithms = hasshServer_Algorithms;
	if ( log_key_algorithm )
		c$ssh$sshka = join_string_vec(capabilities$server_host_key_algorithms, ",");
	}

event ssh_capabilities(c: connection, cookie: string,
    capabilities: SSH::Capabilities)
	{
	# This should really never apply, but just in case the service is not set yet.
	if ( ! c?$ssh )
		return;

	if ( capabilities$is_server && ! c$ssh?$hasshServer )
		{
		get_hasshServer(c, capabilities);
		return;
		}

	if ( ! capabilities$is_server && ! c$ssh?$hassh )
		get_hassh(c, capabilities);
	}
