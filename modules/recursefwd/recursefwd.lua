-- SPDX-License-Identifier: GPL-3.0-or-later
-- Forward recursive sub-queries according to policy rules.
--
-- The policy module only evaluates its rules for the initial query of each
-- request; the internal sub-queries issued by the iterator (NS addresses,
-- DNSSEC lookups, ...) keep using ordinary recursion.  This module re-evaluates
-- a dedicated set of policy rules on every query, including sub-queries, and
-- switches matching ones to forwarding mode.
local ffi = require('ffi')

local kres = require('kres')
local policy = require('kres_modules.policy')

local M = {
	-- Policy rules evaluated for every (sub-)query, most specific first.
	rules = {},
	layer = {},
}

-- Accept either a single address string or a list of them; return the
-- both the target layout understood by policy.forward_convert_targets()
-- (for validation/error semantics) and a plain Lua list of sockaddrs.
local function normalize_target_spec(target)
	local addresses = type(target) == 'table' and target or {target}
	local spec = {}
	for _, address in ipairs(addresses) do
		if type(address) ~= 'string' then
			error('recursefwd: forwarding target must be an IP address string')
		end
		table.insert(spec, {address})
	end
	if #spec == 0 then
		error('recursefwd: no usable forwarding target provided')
	end
	local socks = policy.forward_convert_targets({auth = false}, spec)
	local list = {}
	for index = 0, #spec - 1 do
		list[index + 1] = socks[index]
	end
	return list
end

local function match_suffix(qname, suffix_dname)
	return ffi.C.knot_dname_in_bailiwick(qname, suffix_dname) >= 0
end

-- Build the forwarding action shared by all rule kinds.
local function forward_action(rule)
	return function(state, req)
		local qry = req:current()
		req.options.FORWARD = true
		req.options.NO_MINIMIZE = true
		qry.flags.FORWARD = true
		qry.flags.STUB = false
		qry.flags.ALWAYS_CUT = false
		qry.flags.NO_MINIMIZE = true
		qry.flags.AWAIT_CUT = true

		local added = 0
		for index = 1, #rule.targets do
			local sock = rule.targets[index]
			if ffi.C.kr_forward_add_target(req, sock) == 0 then
				added = added + 1
			end
		end
		if added == 0 then
			error('recursefwd: no usable address in NS set '
			      .. '(check net.ipv4 and net.ipv6 config)')
		end

		log_qry(qry, ffi.C.LOG_GRP_POLICY,
			'recursefwd: forwarding sub-query %s %s\n',
			kres.dname2str(qry:name()), kres.tostring.type[qry.stype])
		return state
	end
end

local function add_rule(matcher, target)
	local rule = {
		matcher = matcher,
		targets = normalize_target_spec(target),
		count = 0,
		suspended = false,
	}
	rule.action = forward_action(rule)
	table.insert(M.rules, rule)
	return rule
end

-- Forward every (sub-)query whose QNAME belongs to the given subtree.
-- `subtree` is a plain domain name, e.g. 'example.com.'.
function M.suffix(subtree, target)
	if type(subtree) ~= 'string' then
		error('recursefwd.suffix: subtree must be a domain name string')
	end
	local zone = kres.str2dname(subtree)
	if zone == nil then
		error('recursefwd.suffix: invalid domain name ' .. tostring(subtree))
	end
	local matcher = function(qname)
		return match_suffix(qname, zone)
	end
	return add_rule(matcher, target)
end

-- Forward every (sub-)query, independently of its QNAME.
function M.all(target)
	return add_rule(function() return true end, target)
end

-- Remove a rule previously returned by M.suffix() or M.all().
function M.del(rule)
	for index, candidate in ipairs(M.rules) do
		if candidate == rule then
			table.remove(M.rules, index)
			return true
		end
	end
	return false
end

-- Re-evaluate the rules on each produced query, not only on the initial one.
function M.layer.produce(state, req)
	if state == kres.FAIL or state == kres.DONE then
		return state
	end
	if #M.rules == 0 then
		return state
	end

	local qry = req:current()
	-- Idempotent: a query already switched to forwarding (e.g. by policy
	-- or by a previous iteration) must not be reconfigured.
	if qry.flags.FORWARD or qry.flags.STUB then
		return state
	end

	local qname = qry:name()
	for _, rule in ipairs(M.rules) do
		if not rule.suspended and rule.matcher(qname) then
			rule.count = rule.count + 1
			return rule.action(state, req)
		end
	end
	return state
end

return M
