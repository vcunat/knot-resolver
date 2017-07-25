-- Speculative prefetching for repetitive and soon-expiring records to reduce latency.
-- @module predict
-- @field queue queue of scheduled queries
-- @field queue_len number of scheduled queries
-- @field period length of prediction history (number of windows)
-- @field window length of the prediction window
local predict = {
	queue = {},
	queue_len = 0,
	batch = 0,
	period = 24,
	window = 15,
	log = {},
}

local function log_verbose(text, ...)
	if not verbose() then return end
	log('[     ][pred] ' .. text, ...)
end

-- Calculate current epoch number (in [1..period], according to the current time)
local function current_epoch()
	if not predict.period or predict.period <= 1 then return nil end
	return math.floor(os.time() / (60 * predict.window))
			% predict.period + 1
end

-- Calculate interval to the next sample (in ms)
-- One sample will take 25-38% of window's time.
local function next_event()
	local jitter = math.floor(predict.window * minute / 8);
	return math.random(2 * jitter, 3 * jitter)
end

-- Resolve queued records and flush the queue
function predict.drain(ev)
	local deleted = 0
	for key, val in pairs(predict.queue) do
		local qtype, qname = key:match('(%S*)%s(.*)')
		worker.resolve(qname, kres.type[qtype], 1, kres.query.NO_CACHE)
		predict.queue[key] = nil
		deleted = deleted + 1
		if deleted >= predict.batch then
			break
		end
	end
	predict.ev_drain = nil
	if deleted > 0 then
		predict.ev_drain = event.after((predict.window * 3) * sec, predict.drain)
	end
	predict.queue_len = predict.queue_len - deleted
	stats['predict.queue'] = predict.queue_len
	collectgarbage('step')
	return 0
end

-- Enqueue queries from set
local function enqueue(queries)
	local queued = 0
	local nr_queries = #queries
	for i = 1, nr_queries do
		local entry = queries[i]
		local key = string.format('%s %s', entry.type, entry.name)
		if not predict.queue[key] then
			predict.queue[key] = 1
			queued = queued + 1
		end
	end
	return queued
end

-- Enqueue queries from same format as predict.queue or predict.log
local function enqueue_from_log(current)
	if not current then return 0 end
	queued = 0
	for key, val in pairs(current) do
		if val and not predict.queue[key] then
			predict.queue[key] = val
			queued = queued + 1
		end
	end
	return queued
end

-- Prefetch soon-to-expire records
function predict.prefetch()
	local queries = stats.expiring()
	stats.clear_expiring()
	return enqueue(queries)
end

-- Sample current epoch, return number of sampled queries
-- i.e. add stats.frequent() into predict.log[epoch_now]
function predict.sample(epoch_now)
	if not epoch_now then return 0 end
	local current = predict.log[epoch_now] or {}
	local queries = stats.frequent()
	stats.clear_frequent()
	local nr_samples = #queries
	for i = 1, nr_samples do
		local entry = queries[i]
		local key = string.format('%s %s', entry.type, entry.name)
		current[key] = 1
	end
	predict.log[epoch_now] = current
	return nr_samples
end

-- Predict queries for the upcoming epoch
local function generate(epoch_now)
	if not epoch_now then return 0 end
	local queued = 0
	local period = predict.period + 1
	for i = 1, predict.period / 2 - 1 do
		local current = predict.log[(epoch_now - i) % period]
		local past = predict.log[(epoch_now - 2*i) % period]
		if current and past then
			for k, v in pairs(current) do
				if past[k] ~= nil and not predict.queue[k] then
					queued = queued + 1
					predict.queue[k] = 1
				end
			end
		end
	end
	return queued
end

function predict.process(ev)
	if not stats then error("'stats' module required") end
	-- Start a new epoch, or continue sampling
	predict.ev_sample = nil
	local epoch_now = current_epoch()
	local nr_queued = 0

	-- End of epoch
	if predict.epoch ~= epoch_now then
		stats['predict.epoch'] = epoch_now
		predict.epoch = epoch_now
		-- enqueue records from upcoming epoch
		nr_queued = enqueue_from_log(predict.log[epoch_now])
		-- predict next epoch
		nr_queued = nr_queued + generate(epoch_now)
		-- clear log for new epoch
		predict.log[epoch_now] = {}
		log_verbose('starting epoch ' .. epoch_now .. ', enqueuing queries: ' .. nr_queued)
	end
	
	-- Sample current epoch
	local nr_frequent = predict.sample(epoch_now)
	-- Prefetch expiring records
	local nr_expiring = predict.prefetch()
	nr_queued = nr_queued + nr_expiring

	log_verbose('queries collected; frequent: ' .. nr_frequent .. ', expiring: ' .. nr_expiring)

	-- Dispatch predicted queries
	if nr_queued > 0 then
		predict.queue_len = predict.queue_len + nr_queued
		predict.batch = predict.queue_len / 5
		if not predict.ev_drain then
			predict.ev_drain = event.after(0, predict.drain)
		end
	end
	predict.ev_sample = event.after(next_event(), predict.process)
	stats['predict.queue'] = predict.queue_len
	stats['predict.learned'] = nr_frequent
	collectgarbage()
end

function predict.init(module)
	if predict.window > 0 then
		predict.epoch = current_epoch()
		predict.ev_sample = event.after(next_event(), predict.process)
	end
end

function predict.deinit(module)
	if predict.ev_sample then event.cancel(predict.ev_sample) end
	if predict.ev_drain then event.cancel(predict.ev_drain) end
	predict.ev_sample = nil
	predict.ev_drain = nil
	predict.log = {}
	predict.queue = {}
	predict.queue_len = 0
	collectgarbage()
end

function predict.config(config)
	-- Reconfigure
	if type(config) ~= 'table' then return end
	if config.window then predict.window = config.window end
	if config.period then predict.period = config.period end
	-- Reinitialize to reset timers
	predict.deinit()
	predict.init()
end

return predict
