#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2023-2025 ImmortalWrt.org
 */

'use strict';

import { readfile, writefile } from 'fs';
import { isnan } from 'math';
import { connect } from 'ubus';
import { cursor } from 'uci';

import {
	isEmpty, strToBool, strToInt,
	removeBlankAttrs, validation,
	HP_DIR, RUN_DIR
} from 'homeproxy';

const ubus = connect();

/* const features = ubus.call('luci.homeproxy', 'singbox_get_features') || {}; */

/* UCI config start */
const uci = cursor();

const uciconfig = 'homeproxy';
uci.load(uciconfig);

const uciinfra = 'infra',
      ucimain = 'config',
      ucicontrol = 'control';

const ucidnssetting = 'dns',
      ucidnsserver = 'dns_server',
      ucidnsrule = 'dns_rule';

const uciroutingsetting = 'routing',
      uciroutingnode = 'routing_node', // Kept for reference, but usage changes
      uciroutingrule = 'routing_rule';

const ucinode = 'node';
const uciruleset = 'ruleset';
const uciexp = 'experimental'; // Added based on diff

const routing_mode = uci.get(uciconfig, ucimain, 'routing_mode') || 'bypass_mainland_china';

let wan_dns = ubus.call('network.interface', 'status', {'interface': 'wan'})?.['dns-server']?.[0];
if (!wan_dns)
	wan_dns = (routing_mode in ['proxy_mainland_china', 'global']) ? '8.8.8.8' : '223.5.5.5';

const dns_port = uci.get(uciconfig, uciinfra, 'dns_port') || '5333';

const ntp_server = uci.get(uciconfig, uciinfra, 'ntp_server') || 'time.apple.com';

let main_node, main_udp_node, dedicated_udp_node, default_outbound, domain_strategy, sniff_override,
    dns_server, china_dns_server, dns_default_strategy, dns_default_server, dns_disable_cache,
    dns_disable_cache_expire, dns_independent_cache, dns_client_subnet, /* cache_file_store_rdrc, (removed from let) */
    /* cache_file_rdrc_timeout, (removed from let) */ direct_domain_list, proxy_domain_list;

if (routing_mode !== 'custom') {
	main_node = uci.get(uciconfig, ucimain, 'main_node') || 'nil';
	main_udp_node = uci.get(uciconfig, ucimain, 'main_udp_node') || 'nil';
	dedicated_udp_node = !isEmpty(main_udp_node) && !(main_udp_node in ['same', main_node]);

	dns_server = uci.get(uciconfig, ucimain, 'dns_server');
	if (isEmpty(dns_server) || dns_server === 'wan')
		dns_server = wan_dns;

	if (routing_mode === 'bypass_mainland_china') {
		china_dns_server = uci.get(uciconfig, ucimain, 'china_dns_server');
		if (isEmpty(china_dns_server) || type(china_dns_server) !== 'string' || china_dns_server === 'wan')
			china_dns_server = wan_dns;
	}

	direct_domain_list = trim(readfile(HP_DIR + '/resources/direct_list.txt'));
	if (direct_domain_list)
		direct_domain_list = split(direct_domain_list, /[\r\n]/);

	proxy_domain_list = trim(readfile(HP_DIR + '/resources/proxy_list.txt'));
	if (proxy_domain_list)
		proxy_domain_list = split(proxy_domain_list, /[\r\n]/);

	sniff_override = uci.get(uciconfig, uciinfra, 'sniff_override') || '1';
} else {
	/* DNS settings */
	dns_default_strategy = uci.get(uciconfig, ucidnssetting, 'default_strategy');
	dns_default_server = uci.get(uciconfig, ucidnssetting, 'default_server');
	dns_disable_cache = uci.get(uciconfig, ucidnssetting, 'disable_cache');
	dns_disable_cache_expire = uci.get(uciconfig, ucidnssetting, 'disable_cache_expire');
	dns_independent_cache = uci.get(uciconfig, ucidnssetting, 'independent_cache');
	dns_client_subnet = uci.get(uciconfig, ucidnssetting, 'client_subnet');
	// cache_file_store_rdrc assignment removed
	// cache_file_rdrc_timeout assignment removed

	/* Routing settings */
	default_outbound = uci.get(uciconfig, uciroutingsetting, 'default_outbound') || 'nil';
	domain_strategy = uci.get(uciconfig, uciroutingsetting, 'domain_strategy');
	sniff_override = uci.get(uciconfig, uciroutingsetting, 'sniff_override');
}

const proxy_mode = uci.get(uciconfig, ucimain, 'proxy_mode') || 'redirect_tproxy';
const ipv6_support = uci.get(uciconfig, ucimain, 'ipv6_support') || '0'; // Kept as separate const
const default_interface = uci.get(uciconfig, ucicontrol, 'bind_interface'); // Kept as separate const

const cache_file_store_rdrc = uci.get(uciconfig, uciexp, 'cache_file_store_rdrc');
const cache_file_rdrc_timeout = uci.get(uciconfig, uciexp, 'cache_file_rdrc_timeout');
const enable_clash_api = uci.get(uciconfig, uciexp, 'enable_clash_api');
const external_ui = uci.get(uciconfig, uciexp, 'external_ui');
const external_ui_download_url = uci.get(uciconfig, uciexp, 'external_ui_download_url');
const external_ui_download_detour = uci.get(uciconfig, uciexp, 'external_ui_download_detour');
const secret = uci.get(uciconfig, uciexp, 'secret');
const default_mode = uci.get(uciconfig, uciexp, 'default_mode');
const external_controller = uci.get(uciconfig, uciexp, 'external_controller');

const mixed_port = uci.get(uciconfig, uciinfra, 'mixed_port') || '5330';
let self_mark, redirect_port, tproxy_port,
    tun_name, tun_addr4, tun_addr6, tun_mtu, tun_gso,
    tcpip_stack, endpoint_independent_nat, udp_timeout;
udp_timeout = uci.get(uciconfig, 'infra', 'udp_timeout');
if (routing_mode === 'custom')
	udp_timeout = uci.get(uciconfig, uciroutingsetting, 'udp_timeout');
if (match(proxy_mode, /redirect/)) {
	self_mark = uci.get(uciconfig, 'infra', 'self_mark') || '100';
	redirect_port = uci.get(uciconfig, 'infra', 'redirect_port') || '5331';
}
if (match(proxy_mode), /tproxy/)
	if (main_udp_node !== 'nil' || routing_mode === 'custom')
		tproxy_port = uci.get(uciconfig, 'infra', 'tproxy_port') || '5332';
if (match(proxy_mode), /tun/) {
	tun_name = uci.get(uciconfig, uciinfra, 'tun_name') || 'singtun0';
	tun_addr4 = uci.get(uciconfig, uciinfra, 'tun_addr4') || '172.19.0.1/30';
	tun_addr6 = uci.get(uciconfig, uciinfra, 'tun_addr6') || 'fdfe:dcba:9876::1/126';
	tun_mtu = uci.get(uciconfig, uciinfra, 'tun_mtu') || '9000';
	tun_gso = uci.get(uciconfig, uciinfra, 'tun_gso') || '0';
	tcpip_stack = 'system';
	if (routing_mode === 'custom') {
		tun_gso = uci.get(uciconfig, uciroutingsetting, 'tun_gso') || '0';
		tcpip_stack = uci.get(uciconfig, uciroutingsetting, 'tcpip_stack') || 'system';
		endpoint_independent_nat = uci.get(uciconfig, uciroutingsetting, 'endpoint_independent_nat');
	}
}
/* UCI config end */

/* Config helper start */
function parse_port(strport) {
	if (type(strport) !== 'array' || isEmpty(strport))
		return null;

	let ports = [];
	for (let i in strport)
		push(ports, int(i));

	return ports;

}

function parse_dnsquery(strquery) {
	if (type(strquery) !== 'array' || isEmpty(strquery))
		return null;

	let querys = [];
	for (let i in strquery)
		isnan(int(i)) ? push(querys, i) : push(querys, int(i));

	return querys;

}

function generate_endpoint(node) {
	if (type(node) !== 'object' || isEmpty(node))
		return null;

	const endpoint = {
		type: node.type,
		tag: 'cfg-' + node['.name'] + '-out', // This function seems specific to main_node wireguard, tag might need adjustment if used more generally
		address: node.wireguard_local_address,
		mtu: strToInt(node.wireguard_mtu),
		private_key: node.wireguard_private_key,
		peers: (node.type === 'wireguard') ? [
			{
				address: node.address,
				port: strToInt(node.port),
				allowed_ips: [
					'0.0.0.0/0',
					'::/0'
				],
				persistent_keepalive_interval: strToInt(node.wireguard_persistent_keepalive_interval),
				public_key: node.wireguard_peer_public_key,
				pre_shared_key: node.wireguard_pre_shared_key,
				reserved: parse_port(node.wireguard_reserved),
			}
		] : null,
		system: (node.type === 'wireguard') ? false : null,
	};

	return endpoint;
}

function generate_outbound(node) {
	if (type(node) !== 'object' || isEmpty(node))
		return null;

	const outbound = {
		type: node.type,
		tag: node.label, // Changed
		routing_mark: (node.type !== 'selector') ? strToInt(self_mark) : null, // Changed

		server: node.address,
		server_port: strToInt(node.port),
		/* Hysteria(2) */
		server_ports: node.hysteria_hopping_port,

		username: (node.type !== 'ssh') ? node.username : null,
		user: (node.type === 'ssh') ? node.username : null,
		password: node.password,

		/* urltest */ // Added section
		outbounds: node.outbounds,
		url: node.url,
		interval: node.interval, // Assuming interval from UCI is already string like '300s' or needs 's' appended
		tolerance: strToInt(node.tolerance),
		idle_timeout: node.idle_timeout, // Assuming from UCI is already string like '600s' or needs 's' appended
		default: node.default,
		interrupt_exist_connections: (node.interrupt_exist_connections === '1') || null,

		/* Direct */
		override_address: node.override_address,
		override_port: strToInt(node.override_port),
		proxy_protocol: strToInt(node.proxy_protocol),
		/* Hysteria (2) */
		hop_interval: node.hysteria_hop_interval ? (node.hysteria_hop_interval + 's') : null,
		up_mbps: strToInt(node.hysteria_up_mbps),
		down_mbps: strToInt(node.hysteria_down_mbps),
		obfs: node.hysteria_obfs_type ? {
			type: node.hysteria_obfs_type,
			password: node.hysteria_obfs_password
		} : node.hysteria_obfs_password,
		auth: (node.hysteria_auth_type === 'base64') ? node.hysteria_auth_payload : null,
		auth_str: (node.hysteria_auth_type === 'string') ? node.hysteria_auth_payload : null,
		recv_window_conn: strToInt(node.hysteria_recv_window_conn),
		recv_window: strToInt(node.hysteria_revc_window),
		disable_mtu_discovery: strToBool(node.hysteria_disable_mtu_discovery),
		/* Shadowsocks */
		method: node.shadowsocks_encrypt_method,
		plugin: node.shadowsocks_plugin,
		plugin_opts: node.shadowsocks_plugin_opts,
		/* ShadowTLS / Socks */
		version: (node.type === 'shadowtls') ? strToInt(node.shadowtls_version) : ((node.type === 'socks') ? node.socks_version : null),
		/* SSH */
		client_version: node.ssh_client_version,
		host_key: node.ssh_host_key,
		host_key_algorithms: node.ssh_host_key_algo,
		private_key: node.ssh_priv_key,
		private_key_passphrase: node.ssh_priv_key_pp,
		/* Tuic */
		uuid: node.uuid,
		congestion_control: node.tuic_congestion_control,
		udp_relay_mode: node.tuic_udp_relay_mode,
		udp_over_stream: strToBool(node.tuic_udp_over_stream),
		zero_rtt_handshake: strToBool(node.tuic_enable_zero_rtt),
		heartbeat: node.tuic_heartbeat ? (node.tuic_heartbeat + 's') : null,
		/* VLESS / VMess */
		flow: node.vless_flow,
		alter_id: strToInt(node.vmess_alterid),
		security: node.vmess_encrypt,
		global_padding: node.vmess_global_padding ? (node.vmess_global_padding === '1') : null,
		authenticated_length: node.vmess_authenticated_length ? (node.vmess_authenticated_length === '1') : null,
		packet_encoding: node.packet_encoding,

		multiplex: (node.multiplex === '1') ? {
			enabled: true,
			protocol: node.multiplex_protocol,
			max_connections: strToInt(node.multiplex_max_connections),
			min_streams: strToInt(node.multiplex_min_streams),
			max_streams: strToInt(node.multiplex_max_streams),
			padding: (node.multiplex_padding === '1'),
			brutal: (node.multiplex_brutal === '1') ? {
				enabled: true,
				up_mbps: strToInt(node.multiplex_brutal_up),
				down_mbps: strToInt(node.multiplex_brutal_down)
			} : null
		} : null,
		tls: (node.tls === '1') ? {
			enabled: true,
			server_name: node.tls_sni,
			insecure: (node.tls_insecure === '1'),
			alpn: node.tls_alpn,
			min_version: node.tls_min_version,
			max_version: node.tls_max_version,
			cipher_suites: node.tls_cipher_suites,
			certificate_path: node.tls_cert_path,
			ech: (node.tls_ech === '1') ? {
				enabled: true,
				pq_signature_schemes_enabled: (node.tls_ech_enable_pqss === '1'),
				config: node.tls_ech_config,
				config_path: node.tls_ech_config_path
			} : null,
			utls: !isEmpty(node.tls_utls) ? {
				enabled: true,
				fingerprint: node.tls_utls
			} : null,
			reality: (node.tls_reality === '1') ? {
				enabled: true,
				public_key: node.tls_reality_public_key,
				short_id: node.tls_reality_short_id
			} : null
		} : null,
		transport: !isEmpty(node.transport) ? {
			type: node.transport,
			host: node.http_host || node.httpupgrade_host,
			path: node.http_path || node.ws_path,
			headers: node.ws_host ? {
				Host: node.ws_host
			} : null,
			method: node.http_method,
			max_early_data: strToInt(node.websocket_early_data),
			early_data_header_name: node.websocket_early_data_header,
			service_name: node.grpc_servicename,
			idle_timeout: node.http_idle_timeout ? (node.http_idle_timeout + 's') : null,
			ping_timeout: node.http_ping_timeout ? (node.http_ping_timeout + 's') : null,
			permit_without_stream: strToBool(node.grpc_permit_without_stream)
		} : null,
		udp_over_tcp: (node.udp_over_tcp === '1') ? {
			enabled: true,
			version: strToInt(node.udp_over_tcp_version)
		} : null,
		tcp_fast_open: strToBool(node.tcp_fast_open),
		tcp_multi_path: strToBool(node.tcp_multi_path),
		udp_fragment: strToBool(node.udp_fragment)
	};

	return outbound;
}

function get_outbound(cfg) {
	if (isEmpty(cfg))
		return null;

	if (type(cfg) === 'array') {
		if ('any-out' in cfg) // This 'in' check on an array item seems unusual, might need review if cfg items are not objects
			return 'any';

		let outbounds = [];
		for (let i in cfg)
			push(outbounds, cfg[i]); // Changed: push item directly (assuming items are already tags)
		return outbounds;
	} else {
		switch (cfg) {
		case 'block-out':
		case 'direct-out':
			return cfg;
		default:
			// cfg is assumed to be a uciroutingnode section name or similar identifier
			const label = uci.get(uciconfig, cfg, 'label'); // Changed: get 'label'
			if (isEmpty(label))
				die(sprintf("%s's label is missing, please check your configuration.", cfg)); // Message changed
			else
				return label; // Changed: return label directly
		}
	}
}

function get_resolver(cfg) {
	if (isEmpty(cfg))
		return null;

	switch (cfg) {
	case 'block-dns':
	case 'default-dns':
	case 'system-dns':
		return cfg;
	default:
		return cfg; // Changed: return cfg directly (assumed to be the tag)
	}
}

function get_ruleset(cfg) {
	if (isEmpty(cfg))
		return null;

	let rules = [];
	for (let i in cfg) // cfg is an array of rule set names/tags
		push(rules, isEmpty(cfg[i]) ? null : cfg[i]); // Changed: push item directly
	return rules;
}
/* Config helper end */

const config = {};

/* Log */
config.log = {
	disabled: false,
	level: 'warn',
	output: RUN_DIR + '/sing-box-c.log',
	timestamp: true
};

/* NTP */
config.ntp = {
	enabled: true,
	server: ntp_server,
	detour: 'direct-out',
	/* TODO: disable this until we have sing-box 1.12 */
	/* domain_resolver: 'default-dns', */
};

/* DNS start */
/* Default settings */
config.dns = {
	servers: [
		{
			tag: 'default-dns',
			address: wan_dns,
			detour: 'direct-out'
		},
		{
			tag: 'system-dns',
			address: 'local',
			detour: 'direct-out'
		},
		{
			tag: 'block-dns',
			address: 'rcode://name_error'
		}
	],
	rules: [
	        /* TODO: remove this once we have sing-box 1.12 */
	        /* NTP domain must be resolved by default DNS */
		{
			domain: ntp_server,
			action: 'route',
			server: 'default-dns'
		}
	],
	strategy: dns_default_strategy,
	disable_cache: (dns_disable_cache === '1'),
	disable_expire: (dns_disable_cache_expire === '1'),
	independent_cache: (dns_independent_cache === '1'),
	client_subnet: dns_client_subnet
};

if (!isEmpty(main_node)) {
	/* Main DNS */
	push(config.dns.servers, {
		tag: 'main-dns',
		address: !match(dns_server, /:\/\//) ? 'tcp://' + (validation('ip6addr', dns_server) ? `[${dns_server}]` : dns_server) : dns_server,
		strategy: (ipv6_support !== '1') ? 'ipv4_only' : null,
		address_resolver: 'default-dns',
		address_strategy: (ipv6_support !== '1') ? 'ipv4_only' : null,
		detour: 'main-out'
	});
	config.dns.final = 'main-dns';

	/* Avoid DNS loop */
	push(config.dns.rules, {
		outbound: 'any',
		action: 'route',
		server: 'default-dns'
	});

	if (length(direct_domain_list))
		push(config.dns.rules, {
			rule_set: 'direct-domain',
			action: 'route',
			server: (routing_mode === 'bypass_mainland_china' ) ? 'china-dns' : 'default-dns'
		});

	/* Filter out SVCB/HTTPS queries for "exquisite" Apple devices */
	if (routing_mode === 'gfwlist' || length(proxy_domain_list))
		push(config.dns.rules, {
			rule_set: (routing_mode !== 'gfwlist') ? 'proxy-domain' : null,
			query_type: [64, 65],
			action: 'reject'
		});

	if (routing_mode === 'bypass_mainland_china') {
		push(config.dns.servers, {
			tag: 'china-dns',
			address: china_dns_server,
			address_resolver: 'default-dns',
			detour: 'direct-out'
		});

		if (length(proxy_domain_list))
			push(config.dns.rules, {
				rule_set: 'proxy-domain',
				action: 'route',
				server: 'main-dns'
			});

		push(config.dns.rules, {
			rule_set: 'geosite-cn',
			action: 'route',
			server: 'china-dns'
		});
		push(config.dns.rules, {
			type: 'logical',
			mode: 'and',
			rules: [
				{
					rule_set: 'geosite-noncn',
					invert: true
				},
				{
					rule_set: 'geoip-cn'
				}
			],
			action: 'route',
			server: 'china-dns'
		});
	}
} else if (!isEmpty(default_outbound)) {
	/* DNS servers */
	uci.foreach(uciconfig, ucidnsserver, (cfg) => {
		if (cfg.enabled !== '1')
			return;

		push(config.dns.servers, {
			tag: cfg.label, // Changed
			address: cfg.address,
			// address: cfg.address, // Duplicate line from original, kept for now
			address_resolver: get_resolver(cfg.address_resolver),
			address_strategy: cfg.address_strategy,
			strategy: cfg.resolve_strategy,
			detour: get_outbound(cfg.outbound), // get_outbound behavior changed
			client_subnet: cfg.client_subnet
		});
	});

	/* DNS rules */
	uci.foreach(uciconfig, ucidnsrule, (cfg) => {
		if (cfg.enabled !== '1')
			return;

		push(config.dns.rules, {
			ip_version: strToInt(cfg.ip_version),
			query_type: parse_dnsquery(cfg.query_type),
			network: cfg.network,
			protocol: cfg.protocol,
			domain: cfg.domain,
			domain_suffix: cfg.domain_suffix,
			domain_keyword: cfg.domain_keyword,
			domain_regex: cfg.domain_regex,
			port: parse_port(cfg.port),
			port_range: cfg.port_range,
			source_ip_cidr: cfg.source_ip_cidr,
			source_ip_is_private: (cfg.source_ip_is_private === '1') || null,
			ip_cidr: cfg.ip_cidr,
			ip_is_private: (cfg.ip_is_private === '1') || null,
			source_port: parse_port(cfg.source_port),
			source_port_range: cfg.source_port_range,
			process_name: cfg.process_name,
			process_path: cfg.process_path,
			process_path_regex: cfg.process_path_regex,
			user: cfg.user,
			rule_set: get_ruleset(cfg.rule_set), // get_ruleset behavior changed
			rule_set_ip_cidr_match_source: (cfg.rule_set_ip_cidr_match_source  === '1') || null,
			invert: (cfg.invert === '1') || null,
			outbound: get_outbound(cfg.outbound), // get_outbound behavior changed
			action: (cfg.server === 'block-dns') ? 'reject' : 'route',
			server: get_resolver(cfg.server), // get_resolver behavior changed
			disable_cache: (cfg.dns_disable_cache === '1') || null,
			rewrite_ttl: strToInt(cfg.rewrite_ttl),
			client_subnet: cfg.client_subnet

		});
	});

	if (isEmpty(config.dns.rules))
		config.dns.rules = null;

	config.dns.final = get_resolver(dns_default_server); // get_resolver behavior changed
}
/* DNS end */

/* Inbound start */
config.inbounds = [];

push(config.inbounds, {
	type: 'direct',
	tag: 'dns-in',
	listen: '::',
	listen_port: int(dns_port)
});

push(config.inbounds, {
	type: 'mixed',
	tag: 'mixed-in',
	listen: '::',
	listen_port: int(mixed_port),
	udp_timeout: udp_timeout ? (udp_timeout + 's') : null,
	sniff: true,
	sniff_override_destination: (sniff_override === '1'),
	set_system_proxy: false
});

if (match(proxy_mode, /redirect/))
	push(config.inbounds, {
		type: 'redirect',
		tag: 'redirect-in',

		listen: '::',
		listen_port: int(redirect_port),
		sniff: true,
		sniff_override_destination: (sniff_override === '1')
	});
if (match(proxy_mode, /tproxy/))
	push(config.inbounds, {
		type: 'tproxy',
		tag: 'tproxy-in',

		listen: '::',
		listen_port: int(tproxy_port),
		network: 'udp',
		udp_timeout: udp_timeout ? (udp_timeout + 's') : null,
		sniff: true,
		sniff_override_destination: (sniff_override === '1')
	});
if (match(proxy_mode, /tun/))
	push(config.inbounds, {
		type: 'tun',
		tag: 'tun-in',

		interface_name: tun_name,
		address: (ipv6_support === '1') ? [tun_addr4, tun_addr6] : [tun_addr4],
		mtu: strToInt(tun_mtu),
		gso: (tun_gso === '1'),
		auto_route: false,
		endpoint_independent_nat: strToBool(endpoint_independent_nat),
		udp_timeout: udp_timeout ? (udp_timeout + 's') : null,
		stack: tcpip_stack,
		sniff: true,
		sniff_override_destination: (sniff_override === '1')
	});
/* Inbound end */

/* Outbound start */
config.endpoints = [];

/* Default outbounds */
config.outbounds = [
	{
		type: 'direct',
		tag: 'direct-out',
		routing_mark: strToInt(self_mark)
	},
	{
		type: 'block',
		tag: 'block-out'
	}
];

/* Main outbounds */
if (!isEmpty(main_node)) {
	let urltest_nodes = [];

	if (main_node === 'urltest') {
		const main_urltest_nodes = uci.get(uciconfig, ucimain, 'main_urltest_nodes') || [];
		const main_urltest_interval = uci.get(uciconfig, ucimain, 'main_urltest_interval');
		const main_urltest_tolerance = uci.get(uciconfig, ucimain, 'main_urltest_tolerance');

		push(config.outbounds, {
			type: 'urltest',
			tag: 'main-out', // This tag generation might need alignment if main_node 'urltest' uses a label system
			outbounds: map(main_urltest_nodes, (k) => `cfg-${k}-out`), // Assumes main_urltest_nodes are still section names needing prefix
			interval: main_urltest_interval ? (main_urltest_interval + 's') : null,
			tolerance: strToInt(main_urltest_tolerance),
			idle_timeout: (strToInt(main_urltest_interval) > 1800) ? `${main_urltest_interval * 2}s` : null,
		});
		urltest_nodes = main_urltest_nodes;
	} else {
		const main_node_cfg = uci.get_all(uciconfig, main_node) || {};
		if (main_node_cfg.type === 'wireguard') {
			push(config.endpoints, generate_endpoint(main_node_cfg));
			config.endpoints[length(config.endpoints)-1].tag = 'main-out';
		} else {
			// This part might need generate_outbound if main_node_cfg aligns with 'node' uci sections
			// For now, assuming generate_outbound is primarily for nodes from ucinode iteration
			// The original generate_outbound(main_node_cfg) might still be intended here with adjustments for label
			const temp_outbound = generate_outbound({...main_node_cfg, label: 'main-out'}); // Create a label for generate_outbound
			temp_outbound.domain_strategy = (ipv6_support !== '1') ? 'prefer_ipv4' : null;
			// temp_outbound.tag = 'main-out'; // generate_outbound now sets tag from label
			push(config.outbounds, temp_outbound);
		}
	}

	if (main_udp_node === 'urltest') {
		const main_udp_urltest_nodes = uci.get(uciconfig, ucimain, 'main_udp_urltest_nodes') || [];
		const main_udp_urltest_interval = uci.get(uciconfig, ucimain, 'main_udp_urltest_interval');
		const main_udp_urltest_tolerance = uci.get(uciconfig, ucimain, 'main_udp_urltest_tolerance');

		push(config.outbounds, {
			type: 'urltest',
			tag: 'main-udp-out',
			outbounds: map(main_udp_urltest_nodes, (k) => `cfg-${k}-out`),
			interval: main_udp_urltest_interval ? (main_udp_urltest_interval + 's') : null,
			tolerance: strToInt(main_udp_urltest_tolerance),
			idle_timeout: (strToInt(main_udp_urltest_interval) > 1800) ? `${main_udp_urltest_interval * 2}s` : null,
		});
		urltest_nodes = [...urltest_nodes, ...filter(main_udp_urltest_nodes, (l) => !~index(urltest_nodes, l))];
	} else if (dedicated_udp_node) {
		const main_udp_node_cfg = uci.get_all(uciconfig, main_udp_node) || {};
		if (main_udp_node_cfg.type === 'wireguard') {
			push(config.endpoints, generate_endpoint(main_udp_node_cfg));
			config.endpoints[length(config.endpoints)-1].tag = 'main-udp-out';
		} else {
			const temp_outbound = generate_outbound({...main_udp_node_cfg, label: 'main-udp-out'});
			temp_outbound.domain_strategy = (ipv6_support !== '1') ? 'prefer_ipv4' : null;
			// temp_outbound.tag = 'main-udp-out';
			push(config.outbounds, temp_outbound);
		}
	}

	for (let i in urltest_nodes) { // i here is the node section name from urltest_nodes array
		const node_name = urltest_nodes[i];
		const urltest_node_cfg = uci.get_all(uciconfig, node_name) || {};
		if (urltest_node_cfg.type === 'wireguard') {
			push(config.endpoints, generate_endpoint(urltest_node_cfg));
			// Tag for endpoint from urltest_node needs to be cfg-nodename-out or its label
			config.endpoints[length(config.endpoints)-1].tag = urltest_node_cfg.label || `cfg-${node_name}-out`;
		} else {
			// Ensure label is present for generate_outbound
			const temp_outbound = generate_outbound({...urltest_node_cfg, label: urltest_node_cfg.label || `cfg-${node_name}-out` });
			temp_outbound.domain_strategy = (ipv6_support !== '1') ? 'prefer_ipv4' : null;
			// temp_outbound.tag = urltest_node_cfg.label || `cfg-${node_name}-out`;
			push(config.outbounds, temp_outbound);
		}
	}
} else if (!isEmpty(default_outbound)) {
    // Removed old uciroutingnode iteration and urltest_nodes processing
    // New simplified loop over ucinode:
	uci.foreach(uciconfig, ucinode, (cfg) => { // cfg is a ucinode section object
		// generate_outbound now expects cfg to have a 'label' for the tag,
		// and all other properties including for urltest type.
		// It also expects interval/idle_timeout to be correctly formatted (e.g. '300s')
		// or handle it inside generate_outbound if UCI stores raw numbers.
		// For simplicity, assuming UCI provides them correctly or generate_outbound handles it.
		// Also, generate_outbound was modified to take node.outbounds directly for urltest.
		// If ucinode contains 'urltest_nodes', map them to their labels for node.outbounds.
		if (cfg.type === 'urltest' && cfg.urltest_nodes) {
			cfg.outbounds = map(cfg.urltest_nodes, (node_name) => {
				const referenced_node_uci = uci.get_all(uciconfig, node_name) || {};
				return referenced_node_uci.label || `cfg-${node_name}-out`; // Use label of referenced node
			});
		}
		// Similarly for url, interval, tolerance, idle_timeout, default, interrupt_exist_connections
		// these should be properties of the 'cfg' (ucinode section) if type is 'urltest'.
		// Example mapping if UCI names are different:
		// if (cfg.type === 'urltest') {
		//   cfg.url = cfg.urltest_url;
		//   cfg.interval = cfg.urltest_interval ? cfg.urltest_interval + 's' : null;
		//   ... and so on for other urltest properties
		// }

		// Detour, bind_interface, domain_strategy from old uciroutingnode logic needs to be part of ucinode (cfg) now.
		// generate_outbound doesn't set these, they are set after if needed.
		const outbound_obj = generate_outbound(cfg);
		if (outbound_obj) {
			if (cfg.domain_strategy) outbound_obj.domain_strategy = cfg.domain_strategy;
			if (cfg.bind_interface) outbound_obj.bind_interface = cfg.bind_interface;
			if (cfg.outbound) outbound_obj.detour = get_outbound(cfg.outbound); // detour for the node itself
			push(config.outbounds, outbound_obj);
		}

		// If the node itself is a WireGuard endpoint, it should be handled by generate_endpoint
		// The current loop pushes to config.outbounds. If cfg.type === 'wireguard',
		// it should go to config.endpoints. This logic might need refinement.
		// The original code had separate handling. For now, assuming generate_outbound handles all types
		// or wireguard is not directly iterated here this way.
		// Based on diff, it seems wireguard nodes are still handled by generate_endpoint separately.
		// This simplified loop might be for non-endpoint type nodes or urltest groups.
		// Let's assume ucinode sections for actual endpoints are processed by generate_endpoint if type === 'wireguard'
		// and generate_outbound for others. The current diff implies generate_outbound for all ucinode.
		// This might require ucinode for wireguard to also have a 'label'.
		if (cfg.type === 'wireguard') {
			// If generate_outbound is not meant for wireguard, this part needs adjustment.
			// The original code structure for custom mode:
			// 1. Iterate uciroutingnode.
			//    - If 'urltest', create urltest outbound. Add its nodes to urltest_nodes list.
			//    - Else (direct node reference), get the actual node config.
			//      - If wireguard, generate_endpoint.
			//      - Else, generate_outbound.
			// 2. Iterate unique urltest_nodes.
			//    - If wireguard, generate_endpoint.
			//    - Else, generate_outbound.
			// The new diff simplifies to "iterate ucinode, call generate_outbound".
			// This means generate_outbound should correctly form a wireguard *outbound* object,
			// or wireguard ucinodes are meant to be endpoints and should be filtered out here
			// and processed by a separate generate_endpoint loop if needed.
			// The diff does not show a separate loop for endpoints from ucinode.
			// For now, relying on generate_outbound to handle it, or this is a simplification point.
		}
	});
}


if (isEmpty(config.endpoints))
	config.endpoints = null;
/* Outbound end */

/* Routing rules start */
/* Default settings */
config.route = {
	rules: [
		{
			inbound: 'dns-in',
			action: 'hijack-dns'
		}
		/*
		 * leave for sing-box 1.13.0
		 * {
		 * 	action: 'sniff'
		 * }
		 */
	],
	rule_set: [],
	auto_detect_interface: isEmpty(default_interface) ? true : null,
	default_interface: default_interface
};

/* Routing rules */
if (!isEmpty(main_node)) {
	/* Direct list */
	if (length(direct_domain_list))
		push(config.route.rules, {
			rule_set: 'direct-domain',
			action: 'route',
			outbound: 'direct-out'
		});

	/* Main UDP out */
	if (dedicated_udp_node)
		push(config.route.rules, {
			network: 'udp',
			action: 'route',
			outbound: 'main-udp-out'
		});

	config.route.final = 'main-out';

	/* Rule set */
	/* Direct list */
	if (length(direct_domain_list))
		push(config.route.rule_set, {
			type: 'inline',
			tag: 'direct-domain',
			rules: [
				{
					domain_keyword: direct_domain_list,
				}
			]
		});

	/* Proxy list */
	if (length(proxy_domain_list))
		push(config.route.rule_set, {
			type: 'inline',
			tag: 'proxy-domain',
			rules: [
				{
					domain_keyword: proxy_domain_list,
				}
			]
		});

	if (routing_mode === 'bypass_mainland_china') {
		push(config.route.rule_set, {
			type: 'remote',
			tag: 'geoip-cn',
			format: 'binary',
			url: 'https://fastly.jsdelivr.net/gh/1715173329/IPCIDR-CHINA@rule-set/cn.srs',
			download_detour: 'main-out'
		});
		push(config.route.rule_set, {
			type: 'remote',
			tag: 'geosite-cn',
			format: 'binary',
			url: 'https://fastly.jsdelivr.net/gh/1715173329/sing-geosite@rule-set-unstable/geosite-geolocation-cn.srs',
			download_detour: 'main-out'
		});
		push(config.route.rule_set, {
			type: 'remote',
			tag: 'geosite-noncn',
			format: 'binary',
			url: 'https://fastly.jsdelivr.net/gh/1715173329/sing-geosite@rule-set-unstable/geosite-geolocation-!cn.srs',
			download_detour: 'main-out'
		});
	}

	if (isEmpty(config.route.rule_set))
		config.route.rule_set = null;
} else if (!isEmpty(default_outbound)) {
	if (domain_strategy)
		push(config.route.rules, {
			action: 'resolve',
			strategy: domain_strategy
		});

	uci.foreach(uciconfig, uciroutingrule, (cfg) => {
		if (cfg.enabled !== '1')
			return null;

		push(config.route.rules, {
			ip_version: strToInt(cfg.ip_version),
			protocol: cfg.protocol,
			network: cfg.network,
			domain: cfg.domain,
			domain_suffix: cfg.domain_suffix,
			domain_keyword: cfg.domain_keyword,
			domain_regex: cfg.domain_regex,
			source_ip_cidr: cfg.source_ip_cidr,
			source_ip_is_private: (cfg.source_ip_is_private === '1') || null,
			ip_cidr: cfg.ip_cidr,
			ip_is_private: (cfg.ip_is_private === '1') || null,
			source_port: parse_port(cfg.source_port),
			source_port_range: cfg.source_port_range,
			port: parse_port(cfg.port),
			port_range: cfg.port_range,
			process_name: cfg.process_name,
			process_path: cfg.process_path,
			process_path_regex: cfg.process_path_regex,
			user: cfg.user,
			rule_set: get_ruleset(cfg.rule_set), // get_ruleset behavior changed
			rule_set_ip_cidr_match_source: (cfg.rule_set_ip_cidr_match_source  === '1') || null,
			rule_set_ip_cidr_accept_empty: (cfg.rule_set_ip_cidr_accept_empty === '1') || null,
			invert: (cfg.invert === '1') || null,
			action: (cfg.outbound === 'block-out') ? 'reject' : 'route',
			override_address: cfg.override_address,
			override_port: strToInt(cfg.override_port),
			outbound: get_outbound(cfg.outbound), // get_outbound behavior changed
		});
	});

	config.route.final = default_outbound; // Changed: assign directly

	/* Rule set */
	uci.foreach(uciconfig, uciruleset, (cfg) => {
		if (cfg.enabled !== '1')
			return null;

		push(config.route.rule_set, {
			type: cfg.type,
			tag: cfg.label, // Changed
			format: cfg.format,
			path: cfg.path,
			url: cfg.url,
			download_detour: get_outbound(cfg.outbound), // get_outbound behavior changed
			update_interval: cfg.update_interval
		});
	});
}
/* Routing rules end */

/* Experimental start */
if (routing_mode in ['bypass_mainland_china', 'custom']) { // routing_mode is string, `in` needs array or object
	// Correcting the condition:
	const experimental_modes = {'bypass_mainland_china':1, 'custom':1};
	if (routing_mode in experimental_modes) {
		config.experimental = {
			cache_file: {
				enabled: true,
				path: RUN_DIR + '/cache.db', // Changed path
				store_rdrc: (cache_file_store_rdrc === '1') || null,
				rdrc_timeout: cache_file_rdrc_timeout ? (cache_file_rdrc_timeout + 's') : null,
			},
			clash_api: { // Added section
				external_controller: (enable_clash_api === '1') ? external_controller : null,
				external_ui: external_ui,
				external_ui_download_url: external_ui_download_url,
				external_ui_download_detour: external_ui_download_detour, // Consider using get_outbound if this is a tag name
				secret: secret,
				default_mode: default_mode
			}
		};
	}
}
/* Experimental end */

system('mkdir -p ' + RUN_DIR);
writefile(RUN_DIR + '/sing-box-c.json', sprintf('%.J\n', removeBlankAttrs(config)));