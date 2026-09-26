#include "core.hpp"

#include "error.hpp"

#include <algorithm>
#include <limits>

namespace orbit::detail {
namespace {

std::int64_t stored_integer(const Json::Value& value) {
    return json_int64(value);
}

std::int64_t absolute_difference(std::int64_t left, std::int64_t right) {
    return left >= right ? left - right : right - left;
}

[[noreturn]] void closed_client() {
    raise(ErrorKind::configuration, "client_closed");
}

} // namespace

void ClientState::persist_record_locked() {
    if (!persistent || !installed_storage || persistent_record.isNull()) {
        raise(ErrorKind::storage, "installation_storage_unavailable");
    }
    persistent_record["generation"] = static_cast<Json::UInt64>(current_generation);
    persistent_record["credential"] = credential
        ? credential_json(*credential) : Json::Value(Json::nullValue);
    commit_persistent_locked(persistent_record);
}

void ClientState::commit_persistent_locked(Json::Value record) {
    if (persistence_failed.load(std::memory_order_relaxed)) {
        raise(ErrorKind::storage, "installation_state_write_failed");
    }
    try {
        const auto bytes = persistent_codec::encode(config, installed_storage->provider(), record);
        installed_storage->save(bytes);
        persistent_record = std::move(record);
    } catch (...) {
        persistence_failed.store(true, std::memory_order_relaxed);
        claims.reset();
        anchor.reset();
        transient = true;
        worker_cancelled.store(true, std::memory_order_relaxed);
        wake_worker();
        throw;
    }
}

void ClientState::checkpoint_persistent_locked(bool force) {
    if (!persistent || !installed_storage || !claims || !anchor ||
        !persistent_record.isObject() || persistent_record["access"].isNull()) {
        return;
    }
    const auto steady_now = std::chrono::steady_clock::now();
    if (!force && last_checkpoint != std::chrono::steady_clock::time_point{} &&
        steady_now - last_checkpoint < std::chrono::seconds(60)) {
        return;
    }
    try {
        const auto wall = capture_clock().wall_seconds;
        const auto server = anchor->now();
        auto& access = persistent_record["access"];
        const auto previous_wall = stored_integer(access["wall_high_water"]);
        const auto previous_server = stored_integer(access["server_high_water"]);
        if (wall < previous_wall || server < previous_server ||
            absolute_difference(server - previous_server, wall - previous_wall) > 30) {
            raise(ErrorKind::clock_uncertain, "clock_uncertain");
        }
        access["wall_high_water"] = static_cast<Json::Int64>(wall);
        access["server_high_water"] = static_cast<Json::Int64>(server);
    } catch (const Error& error) {
        if (error.kind() != ErrorKind::clock_uncertain) throw;
        claims.reset();
        anchor.reset();
        transient = true;
        persistent_record["access"] = Json::Value(Json::nullValue);
        // Invalid clock evidence must not become reusable after another restart.
        persist_record_locked();
        throw;
    }
    persist_record_locked();
    last_checkpoint = steady_now;
}

bool ClientState::restore_persistent_cache(bool allow_offline) {
    std::lock_guard<std::mutex> lock(mutex);
    if (!persistent || persistent_record.isNull() || persistent_record["access"].isNull() ||
        !credential) {
        return false;
    }
    auto discard = [&] {
        claims.reset();
        anchor.reset();
        transient = true;
        persistent_record["access"] = Json::Value(Json::nullValue);
        persist_record_locked();
    };
    try {
        const auto& cached = persistent_record["access"];
        const auto received_server = stored_integer(cached["received_server_time"]);
        const auto received_wall = stored_integer(cached["received_wall_time"]);
        const auto server_high = stored_integer(cached["server_high_water"]);
        const auto wall_high = stored_integer(cached["wall_high_water"]);
        const auto clock = capture_clock();
        const auto wall = clock.wall_seconds;
        const auto elapsed = clock.elapsed_nanoseconds;
        if (received_server <= 0 || received_wall <= 0 || server_high < received_server ||
            wall_high < received_wall || wall < wall_high || wall < received_wall ||
            elapsed < 0 ||
            absolute_difference(server_high - received_server, wall_high - received_wall) > 30 ||
            wall - received_wall > std::numeric_limits<std::int64_t>::max() - received_server) {
            discard();
            return false;
        }
        const auto projected = received_server + (wall - received_wall);
        const auto estimated_server = std::max(server_high, projected);
        std::optional<std::int64_t> licence_expiry;
        if (!cached["licence_expires_at"].isNull()) {
            licence_expiry = stored_integer(cached["licence_expires_at"]);
        }
        auto restored_keys = GrantKeys::parse(cached["jwks"]);
        if (restored_keys.size() != 1) {
            discard();
            return false;
        }
        const auto& saved = *credential;
        const std::optional<std::string_view> fingerprint = config.fingerprint
            ? std::optional<std::string_view>(config.fingerprint->value) : std::nullopt;
        const std::optional<std::string_view> provider = config.fingerprint
            ? std::optional<std::string_view>(config.fingerprint->provider) : std::nullopt;
        const std::optional<std::string_view> licence(saved.licence_id);
        GrantExpected expected{
            config.issuer, config.application_id, config.environment_id, licence,
            saved.activation_id, *config.installation_id, fingerprint, provider,
            saved.expires_at, licence_expiry, received_server,
        };
        auto restored_claims = restored_keys.verify(cached["jws"].asString(), expected);
        if (!restored_claims.offline_allowed || estimated_server >= restored_claims.expires_at) {
            discard();
            return false;
        }
        if (!allow_offline) return false;
        keys = std::move(restored_keys);
        claims = std::move(restored_claims);
        anchor = ClockAnchor{estimated_server, elapsed, wall};
        transient = true;
        // Keep the bounded retry deadline from the failed online attempt.
        try {
            checkpoint_persistent_locked(true);
        } catch (...) {
            claims.reset();
            anchor.reset();
            throw;
        }
        return true;
    } catch (const Error& error) {
        if (error.kind() == ErrorKind::storage || error.kind() == ErrorKind::corrupt_state) {
            throw;
        }
        discard();
        return false;
    } catch (...) {
        discard();
        return false;
    }
}

void ClientState::begin_call() {
    std::lock_guard<std::mutex> lock(lifecycle_mutex);
    if (closing || closed) closed_client();
    if (persistence_failed.load(std::memory_order_relaxed)) raise(ErrorKind::storage, "installation_state_write_failed");
    ++active_calls;
}

void ClientState::end_call() noexcept {
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex);
        if (active_calls > 0) --active_calls;
    }
    lifecycle_changed.notify_all();
}

void ClientState::start_worker() {
    std::lock_guard<std::mutex> lock(lifecycle_mutex);
    if (!persistent || worker_started || closing || closed) return;
    worker_started = true;
    worker = std::thread([this] { worker_loop(); });
}

void ClientState::wake_worker() noexcept {
    worker_epoch.fetch_add(1, std::memory_order_relaxed);
    lifecycle_changed.notify_all();
}

void ClientState::worker_loop() noexcept {
    while (!worker_cancelled.load(std::memory_order_relaxed)) {
        const auto observed_epoch = worker_epoch.load(std::memory_order_relaxed);
        bool refresh_now = false;
        bool checkpoint_now = false;
        auto wake_at = std::chrono::steady_clock::now() + std::chrono::hours(1);
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (!persistent || !credential || !persistent_record["pending_activation"].isNull()) {
                // A pending key mutation is resumed only by the caller with the same key.
            } else if (retry_deadline) {
                const auto now = std::chrono::steady_clock::now();
                if (now >= *retry_deadline) {
                    refresh_now = true;
                } else {
                    wake_at = std::min(wake_at, *retry_deadline);
                }
            } else if (!claims || !anchor) {
                refresh_now = true;
            } else {
                try {
                    const auto state = snapshot_locked(true);
                    if (state["access"] == "refresh_required" ||
                        state["access"] == "expired" || state["access"] == "offline") {
                        refresh_now = true;
                    } else {
                        const auto until = std::max<std::int64_t>(
                            1, claims->refresh_after - anchor->now());
                        wake_at = std::min(wake_at,
                            std::chrono::steady_clock::now() + std::chrono::seconds(until));
                    }
                } catch (...) {
                    refresh_now = true;
                }
            }
            if (claims && anchor) {
                if (last_checkpoint == std::chrono::steady_clock::time_point{} ||
                    std::chrono::steady_clock::now() - last_checkpoint >=
                        std::chrono::seconds(60)) {
                    checkpoint_now = true;
                } else {
                    wake_at = std::min(wake_at, last_checkpoint +
                        std::chrono::seconds(60));
                }
            }
        }

        if (checkpoint_now) {
            try {
                std::lock_guard<std::mutex> lock(mutex);
                checkpoint_persistent_locked(false);
            } catch (...) {
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    claims.reset();
                    anchor.reset();
                    transient = true;
                }
                worker_cancelled.store(true, std::memory_order_relaxed);
                break;
            }
        }
        if (refresh_now && !worker_cancelled.load(std::memory_order_relaxed)) {
            try {
                (void)refresh(worker_cancelled, true);
            } catch (...) {
                // Transport failures normally set this deadline. Other failures
                // before a reply must not turn a due grant into a busy loop.
                std::lock_guard<std::mutex> lock(mutex);
                const auto earliest = std::chrono::steady_clock::now() + std::chrono::seconds(15);
                if (!retry_deadline || *retry_deadline < earliest) retry_deadline = earliest;
            }
            continue;
        }

        std::unique_lock<std::mutex> wait_lock(lifecycle_mutex);
        if (worker_cancelled.load(std::memory_order_relaxed) || closing) break;
        lifecycle_changed.wait_until(wait_lock, wake_at, [this, observed_epoch] {
            return worker_cancelled.load(std::memory_order_relaxed) || closing ||
                worker_epoch.load(std::memory_order_relaxed) != observed_epoch;
        });
    }
}

void ClientState::close() {
    {
        // Acceptance holds this mutex through persistence, so close cannot
        // begin between its cancellation fence and the durable commit.
        std::unique_lock<std::mutex> state_lock(mutex);
        std::unique_lock<std::mutex> lock(lifecycle_mutex);
        if (closed) return;
        if (closing) {
            state_lock.unlock();
            lifecycle_changed.wait(lock, [this] { return closed; });
            return;
        }
        closing = true;
        if (persistent) owner_cancelled->store(true, std::memory_order_relaxed);
        worker_cancelled.store(true, std::memory_order_relaxed);
    }
    lifecycle_changed.notify_all();

    if (worker.joinable()) {
        if (worker.get_id() == std::this_thread::get_id()) {
            worker.detach();
        } else {
            worker.join();
        }
    }

    {
        std::unique_lock<std::mutex> lock(lifecycle_mutex);
        lifecycle_changed.wait(lock, [this] { return active_calls == 0; });
    }

    std::exception_ptr failure;
    {
        std::lock_guard<std::mutex> lock(mutex);
        try {
            checkpoint_persistent_locked(true);
        } catch (...) {
            failure = std::current_exception();
        }
        // Every active call has settled; no generation advance is needed and
        // cleanup must also work at the durable generation limit.
        credential.reset();
        claims.reset();
        anchor.reset();
        customer.reset();
        transient = false;
        retry_deadline.reset();
        persistent_record = Json::Value(Json::nullValue);
        installed_storage.reset();
        storage.reset();
    }
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex);
        closed = true;
    }
    lifecycle_changed.notify_all();
    if (failure) std::rethrow_exception(failure);
}

ClientState::~ClientState() noexcept {
    try {
        close();
    } catch (...) {
        // Destruction releases the lease even when the explicit checkpoint failed.
    }
}

} // namespace orbit::detail
