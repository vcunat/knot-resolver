-- Module interface
local ffi = require('ffi')
local M = {}
local addr_buf = ffi.new('char[16]')

--[[
Implementation notes:
	This part of RFC 6147 isn't implemented:
	> The implementation SHOULD support mapping of separate IPv4 address
	> ranges to separate IPv6 prefixes for AAAA record synthesis.  This
	> allows handling of special use IPv4 addresses [RFC5735].

	Also the exclusion prefixes are not implemented, sec. 5.1.4.

	TTL of the negative answer isn't taken into account, sec. 5.1.7.4.
]]

-- Config
function M.config (confstr)
	if confstr == nil then return end
	M.proxy = kres.str2ip(confstr)
	if M.proxy == nil then error('[dns64] "'..confstr..'" is not a valid address') end
end

-- Layers
M.layer = { }
function M.layer.consume(state, req, pkt)
	if state == kres.FAIL then return state end
	pkt = kres.pkt_t(pkt)
	req = kres.request_t(req)
	local qry = req:current()
	-- Observe only final answers in IN class.
	if M.proxy == nil or not qry.flags.RESOLVED or pkt:qclass() ~= kres.class.IN then
		return state
	end
	-- Synthetic AAAA from marked A responses
	local answer = pkt:section(kres.section.ANSWER)

	-- Observe final AAAA NODATA responses to the current SNAME.
	local is_nodata = pkt:rcode() == kres.rcode.NOERROR and #answer == 0
	if pkt:qtype() == kres.type.AAAA and is_nodata and pkt:qname() == qry:name()
			and qry.flags.RESOLVED and qry.parent == nil then
		-- Start a *marked* corresponding A sub-query.
		local extraFlags = kres.mk_qflags({})
		extraFlags.DNSSEC_WANT = qry.flags.DNSSEC_WANT
		extraFlags.AWAIT_CUT = true
		extraFlags.DNS64_MARK = true
		req:push(pkt:qname(), kres.type.A, kres.class.IN, extraFlags, qry)
		return state
	end

	-- Observe answer to the marked sub-query, and convert all A records in ANSWER
	-- to corresponding AAAA records to be put into the request's answer.
	if not qry.flags.DNS64_MARK then return state end
	local section = ffi.C.knot_pkt_section(pkt, kres.section.ANSWER)
	for i = 1, section.count do
		local orig = ffi.C.knot_pkt_rr(section, i - 1)
		if orig.type == kres.type.A then
			-- Disable GC, as this object doesn't own owner or RDATA, it's just a reference
			local rrs = ffi.gc(kres.rrset(nil, kres.type.AAAA, orig.rclass), nil)
			rrs._owner = ffi.cast('knot_dname_t *', orig:owner()) -- explicit cast needed here
			for k = 1, orig.rrs.rr_count do
				local rdata = orig:rdata( k - 1 )
				ffi.copy(addr_buf, M.proxy, 12)
				ffi.copy(addr_buf + 12, rdata, 4)
				ffi.C.knot_rrset_add_rdata(rrs, ffi.string(addr_buf, 16), 16, orig:ttl(), req.pool)
			end
			ffi.C.kr_ranked_rrarray_add(
				req.answ_selected,
				rrs,
				ffi.C.KR_RANK_OMIT,
				true,
				qry.uid,
				req.pool)
		end
	end
end

return M
