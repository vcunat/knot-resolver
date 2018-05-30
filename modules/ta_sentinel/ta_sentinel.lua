local M = {}
M.layer = {}

function M.layer.finish(state, req, pkt)
	local kreq = kres.request_t(req)

	if bit.band(state, kres.DONE) == 0 then
		return state end -- not resolved yet, exit

	local qry = kreq:resolved()
	if qry.parent ~= nil then
		return state end -- an internal query, exit

	local qf = qry.flags
	if qf.CACHED or not qf.DNSSEC_WANT or qf.DNSSEC_INSECURE
			or qf.DNSSEC_BOGUS or kreq.answer:cd() then
		return state end -- no trust anchor or insecure domain, exit

	local kpkt = kres.pkt_t(pkt)
	if kpkt:qtype() ~= kres.type.A and kpkt:qtype() ~= kres.type.AAAA then
		return state end

	if kpkt:qclass() ~= kres.class.IN then
		return state end

	-- fast filter by the length of the first label
	local label_len = qry:name():byte(1)
	if label_len ~= 29 and label_len ~= 30 then
		return state end
	-- end of hot path
	-- check the label name
	local qname = kres.dname2str(qry:name()):lower()
	local sentype, keytag
	if label_len == 29 then
		sentype = true
		keytag = qname:match('^root%-key%-sentinel%-is%-ta%-(%x+)%.')
	elseif label_len == 30 then
		sentype = false
		keytag = qname:match('^root%-key%-sentinel%-not%-ta%-(%x+)%.')
	end
	-- check keytag from the label
	keytag = tonumber(keytag)
	if not keytag or math.floor(keytag) ~= keytag then
		return state end -- pattern did not match, exit
	if keytag < 0 or keytag > 0xffff then
		return state end -- invalid keytag?!, exit

	if verbose() then
		log('[ta_sentinel] key tag: ' .. keytag .. ', sentinel: ' .. tostring(sentype))
	end

	local found = false
	for keyidx = 1, #trust_anchors.keysets['\0'] do
		local key = trust_anchors.keysets['\0'][keyidx]
		if keytag == key.key_tag then
			found = (key.state == "Valid")
			if verbose() then
				log('[ta_sentinel] found keytag ' .. keytag .. ', key state ' .. key.state)
			end
		end
	end

	if sentype ~= found then -- expected key is not there, or unexpected key is there
		kpkt:clear_payload()
		kpkt:rcode(kres.rcode.SERVFAIL)
		kpkt:ad(false)
	end
	return state -- do not break resolution process
end

return M
