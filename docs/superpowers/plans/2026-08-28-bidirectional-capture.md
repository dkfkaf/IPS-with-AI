# Bidirectional Host Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Observe host IPv4 INPUT and OUTPUT traffic in one NFQUEUE, build complete remote-initiated bidirectional flows, and manage the required iptables rules automatically.

**Architecture:** `PacketSource` derives packet direction from the NFQUEUE hook and passes it into `PacketCapture`. `FlowManager` fixes each flow's origin at creation, tracks both origins, but exposes rule statistics only for inbound packets belonging to remote-initiated flows; `PacketCapture` sends only those flows to `FlowConsumer`. A dedicated RAII `FirewallQueueGuard` owns one marked iptables chain and installs or removes INPUT/OUTPUT jumps around the NFQUEUE receive loop.

**Tech Stack:** C++17, libnetfilter_queue, Linux netfilter/iptables, glog, CMake

**Spec:** `docs/superpowers/specs/2026-08-27-bidirectional-capture-design.md`

## Global Constraints

- Scope is host IPv4 `INPUT` and `OUTPUT`; exclude IPv6, `FORWARD`, routers, bridges, and L7 payload inspection.
- Use one NFQUEUE and one packet-processing thread; do not introduce locking.
- RuleEngine, Whitelist, and BlockList DROP behavior applies only to inbound traffic; outbound verdict is always ACCEPT.
- Deliver only `REMOTE_INITIATED` flows to `FlowConsumer`; track `LOCAL_INITIATED` flows only to classify their inbound responses.
- Use `/usr/sbin/iptables` through `fork` and `execv`; never invoke a shell or interpolate a command string.
- Manage only chain `IPS_WITH_AI` with markers `ips-with-ai-managed` and `ips-with-ai-owned`; never modify an unowned same-name chain.
- Every NFQUEUE rule must include `--queue-bypass`.
- Preserve all existing test files. Per user decision, do not add, delete, modify, or run GTest code in this implementation pass.
- Preserve unrelated dirty-worktree changes. Do not create implementation commits unless the user separately requests them.

---

### Task 1: Packet direction and flow origin

**Files:**
- Create: `src/capture/packet_direction.h`
- Modify: `src/capture/packet_source.h`
- Modify: `src/capture/packet_source.cpp`
- Modify: `src/flow/flow.h`
- Modify: `src/flow/flow_manager.h`
- Modify: `src/flow/flow_manager.cpp`

**Interfaces:**
- Produces: `enum class PacketDirection { INBOUND, OUTBOUND, UNKNOWN };`
- Produces: `enum class FlowOrigin { REMOTE_INITIATED, LOCAL_INITIATED };`
- Produces: `const SourceStats* FlowManager::observe_packet(const ParsedPacket&, PacketDirection, TimePoint);`
- Preserves: `const SourceStats* FlowManager::add_packet(const ParsedPacket&, TimePoint);` as an inbound compatibility wrapper.
- Changes: `PacketSource::PacketHandler` to `std::function<bool(const uint8_t*, size_t, PacketDirection)>`.

- [ ] **Step 1: Add the shared direction type**

Create a dependency-light header used by capture and flow code:

```cpp
enum class PacketDirection {
    INBOUND,
    OUTBOUND,
    UNKNOWN,
};
```

- [ ] **Step 2: Translate the NFQUEUE hook into packet direction**

In `PacketSource::on_packet_received`, map the packet header hook before invoking the handler:

```cpp
PacketDirection direction = PacketDirection::UNKNOWN;
if (packet_header->hook == NF_INET_LOCAL_IN) {
    direction = PacketDirection::INBOUND;
} else if (packet_header->hook == NF_INET_LOCAL_OUT) {
    direction = PacketDirection::OUTBOUND;
}

accept = self->handler_(payload, static_cast<size_t>(payload_len), direction);
```

Keep the existing fail-open exception and missing-payload behavior unchanged. The packet ID is still mandatory because a verdict cannot be sent without it.

- [ ] **Step 3: Store immutable flow origin**

Add `FlowOrigin origin = FlowOrigin::REMOTE_INITIATED;` to `Flow`. The default preserves the behavior of existing aggregate construction and the legacy `add_packet` path.

- [ ] **Step 4: Make flow lookup return direction and origin context**

Change the private flow update helper to return the updated flow and whether the packet matched its forward key:

```cpp
struct UpdatedFlow {
    Flow* flow;
    bool is_forward;
};

std::optional<UpdatedFlow> update_flow(const ParsedPacket& packet,
                                       PacketDirection direction,
                                       TimePoint now);
```

When no tuple exists, create a flow only below `max_flows_`, set its key to the packet tuple, and choose origin from direction:

```cpp
flow.origin = direction == PacketDirection::OUTBOUND
                  ? FlowOrigin::LOCAL_INITIATED
                  : FlowOrigin::REMOTE_INITIATED;
```

Do not create state for `UNKNOWN`. Keep reverse-tuple matching, IAT, flag counters, FIN completion, and source-key indexing unchanged.

- [ ] **Step 5: Expose direction-aware observation**

Implement the public entry point in this order:

```cpp
const SourceStats* FlowManager::observe_packet(const ParsedPacket& packet,
                                               PacketDirection direction,
                                               TimePoint now) {
    if (direction == PacketDirection::UNKNOWN) {
        return nullptr;
    }
    const auto updated = update_flow(packet, direction, now);
    if (!updated.has_value()) {
        return nullptr;
    }
    if (direction != PacketDirection::INBOUND || !updated->is_forward ||
        updated->flow->origin != FlowOrigin::REMOTE_INITIATED) {
        return nullptr;
    }
    return update_source_stats(packet, now);
}
```

Implement `add_packet` as `observe_packet(packet, PacketDirection::INBOUND, now)`. This keeps old callers source-compatible while outbound responses never pollute port-scan or SYN-flood source statistics.

- [ ] **Step 6: Run static consistency checks**

Run:

```powershell
rg -n "PacketHandler|handler_|observe_packet|add_packet|FlowOrigin|PacketDirection" src
git diff --check
```

Expected: every handler accepts direction, only the compatibility wrapper calls directionless `add_packet`, and `git diff --check` reports no whitespace errors.

---

### Task 2: Direction-specific packet policy and AI delivery

**Files:**
- Modify: `src/capture/packet_capture.h`
- Modify: `src/capture/packet_capture.cpp`

**Interfaces:**
- Consumes: `PacketDirection`, `FlowManager::observe_packet`, and `Flow::origin` from Task 1.
- Changes: `bool PacketCapture::on_packet(const uint8_t*, size_t, PacketDirection);`
- Produces: private `handle_inbound` and `handle_outbound` verdict paths.

- [ ] **Step 1: Pass direction through the PacketSource callback**

Update the constructor callback and `on_packet` declaration:

```cpp
[this](const uint8_t* data, size_t len, PacketDirection direction) {
    return on_packet(data, len, direction);
}
```

- [ ] **Step 2: Reject unknown direction from state updates**

At the start of `on_packet`, return ACCEPT for `UNKNOWN` before parsing or mutating any flow, rule, whitelist, or block-list state. Log a warning identifying the unsupported hook path.

- [ ] **Step 3: Preserve the inbound enforcement order**

Move the current policy into `handle_inbound(const ParsedPacket&, TimePoint)` with this exact order:

```text
source whitelist -> ACCEPT
source block list -> DROP
no ports -> ACCEPT
observe inbound packet
no SourceStats -> ACCEPT
rule hit -> discard source flows, add TTL block, DROP
extract completed flow -> consume
ACCEPT
```

The rule-hit packet remains immediately dropped. Do not call `extract_completed` after discarding its source flows.

- [ ] **Step 4: Add the outbound observation path**

Implement `handle_outbound(const ParsedPacket&, TimePoint)` so that it always returns true:

```cpp
const uint32_t dst_ip = packet.tuple.dst_ip;
if (whitelist_.is_whitelisted(dst_ip) || block_list_.is_blocked(dst_ip, now) ||
    !packet.has_ports) {
    return true;
}
flow_manager_.observe_packet(packet, PacketDirection::OUTBOUND, now);
if (auto completed = flow_manager_.extract_completed(packet.tuple); completed.has_value()) {
    consume_flow(std::move(*completed));
}
return true;
```

Never call `RuleEngine::check` and never return DROP in this path.

- [ ] **Step 5: Filter local-origin flows before AI record construction**

Make origin the first `consume_flow` guard:

```cpp
if (ended_flow.flow.origin != FlowOrigin::REMOTE_INITIATED) {
    return;
}
```

Retain the one-packet, whitelist, block-list, feature-schema, and queue-full behavior for remote flows.

- [ ] **Step 6: Check every verdict path**

Run:

```powershell
rg -n "return false|RuleEngine|rule_engine_|observe_packet|consume_flow" src/capture/packet_capture.*
git diff --check
```

Expected: `return false` exists only in inbound block-list/rule-hit handling; outbound calls observation but no rule check; local-origin flows exit before `FlowRecord` construction.

---

### Task 3: Automatic iptables lifecycle

**Files:**
- Create: `src/capture/firewall_queue_guard.h`
- Create: `src/capture/firewall_queue_guard.cpp`
- Modify: `src/capture/packet_capture.h`
- Modify: `src/capture/packet_capture.cpp`
- Modify: `src/main.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Produces: `explicit FirewallQueueGuard(uint16_t queue_num);`
- Produces: `bool FirewallQueueGuard::install();`
- Produces: `bool FirewallQueueGuard::uninstall();`
- Consumes: the validated `Config::queue_num` and wraps `PacketSource::loop()`.

- [ ] **Step 1: Define the RAII firewall owner**

The header owns only queue configuration and installation state:

```cpp
class FirewallQueueGuard {
 public:
    explicit FirewallQueueGuard(uint16_t queue_num);
    ~FirewallQueueGuard();

    FirewallQueueGuard(const FirewallQueueGuard&) = delete;
    FirewallQueueGuard& operator=(const FirewallQueueGuard&) = delete;

    bool install();
    bool uninstall();

 private:
    bool remove_owned_chain();
    uint16_t queue_num_;
    bool installed_ = false;
};
```

The destructor performs best-effort `uninstall()` and never throws.

- [ ] **Step 2: Execute iptables without a shell**

In the implementation file, create a translation-unit helper taking `std::vector<std::string>` arguments. Prepend `/usr/sbin/iptables` and `-w`, build a null-terminated `char* argv[]`, then use `fork`, `execv`, and `waitpid`. The child calls `_exit(127)` when `execv` fails. The parent retries `waitpid` on `EINTR` and returns the child exit code or `-1` for fork/wait/signal failure.

Use named constants:

```cpp
constexpr char IPTABLES_PATH[] = "/usr/sbin/iptables";
constexpr char CHAIN_NAME[] = "IPS_WITH_AI";
constexpr char JUMP_COMMENT[] = "ips-with-ai-managed";
constexpr char OWNER_COMMENT[] = "ips-with-ai-owned";
```

- [ ] **Step 3: Detect ownership before cleanup**

Use `iptables -n -L IPS_WITH_AI` to determine whether the chain exists. If it exists, require this exact marker rule before changing anything:

```text
-C IPS_WITH_AI -m comment --comment ips-with-ai-owned -j RETURN
```

If the chain exists without the marker, log an error and return false. For an owned chain, repeatedly check and delete the exact marked jumps from both INPUT and OUTPUT, then flush and delete the chain. Nonzero from a jump `-C` ends that chain's duplicate-removal loop; failures while deleting, flushing, or deleting the chain are fatal and logged.

- [ ] **Step 4: Install the owned chain transactionally**

After stale cleanup succeeds, execute these operations in order:

```text
-N IPS_WITH_AI
-A IPS_WITH_AI -j NFQUEUE --queue-num <queue_num> --queue-bypass
-A IPS_WITH_AI -m comment --comment ips-with-ai-owned -j RETURN
-I INPUT 1 -m comment --comment ips-with-ai-managed -j IPS_WITH_AI
-I OUTPUT 1 -m comment --comment ips-with-ai-managed -j IPS_WITH_AI
```

Track whether this invocation created the chain and each jump. On any failure, delete created jumps in reverse order, flush the newly created chain, delete it, set `installed_ = false`, and return false. This rollback may remove the just-created chain even if adding its ownership marker failed; it must not use stale-chain ownership detection for resources known to belong to the current process.

- [ ] **Step 5: Make uninstall idempotent**

`uninstall()` returns true when nothing managed exists. When an owned chain exists, remove all exact marked jump duplicates, flush it, and delete it. Clear `installed_` after successful cleanup. Never remove unrelated INPUT/OUTPUT rules or an unmarked same-name chain.

- [ ] **Step 6: Wrap the receive loop in the correct resource order**

Add `FirewallQueueGuard firewall_;` before `PacketSource source_` and initialize both with the same queue number. Update `PacketCapture::start()`:

```cpp
if (!source_.open()) {
    return false;
}
if (!firewall_.install()) {
    source_.close();
    return false;
}
const bool loop_ok = source_.loop();
const bool firewall_ok = firewall_.uninstall();
const bool close_ok = source_.close();
return loop_ok && firewall_ok && close_ok;
```

Removing the jump before closing NFQUEUE prevents new packets from entering the queue during normal shutdown. `--queue-bypass` keeps traffic moving after an uncatchable process death.

- [ ] **Step 7: Register the source and replace the manual-rule log**

Add `src/capture/firewall_queue_guard.cpp` to the `ips` target only. Replace the sample manual iptables command in `main.cpp` with a message that INPUT/OUTPUT queue rules are managed automatically for the configured queue.

- [ ] **Step 8: Run source-level safety checks**

Run:

```powershell
rg -n "system\(|popen\(|/bin/sh|execv|queue-bypass|ips-with-ai-managed|ips-with-ai-owned" src
rg -n "firewall_queue_guard.cpp" CMakeLists.txt
git diff --check
```

Expected: no shell execution API, every rule token is passed through `execv`, both markers and `--queue-bypass` are present, the source is in CMake, and no whitespace errors are reported.

---

### Task 4: Documentation and verification handoff

**Files:**
- Modify: `README.md`
- Modify: `docs/design/flow_features.md`
- Modify: `docs/design/online_inference.md`

**Interfaces:**
- Consumes: final runtime behavior from Tasks 1-3.
- Produces: operator instructions and an explicit Ubuntu VM verification matrix.

- [ ] **Step 1: Replace manual firewall setup instructions**

Document that `sudo ./build/ips` automatically creates and removes the marked INPUT/OUTPUT rules. State that root and `/usr/sbin/iptables` are required, startup aborts on an unowned `IPS_WITH_AI` chain, and `--queue-bypass` prevents stale rules from blocking traffic after force-kill.

- [ ] **Step 2: Correct the feature and inference scope**

Replace the current INPUT-only limitation note with the implemented behavior: INPUT is the enforcement direction, OUTPUT supplements backward-flow statistics, local-initiated flows are not sent to AI, and IPv6/FORWARD remain out of scope.

- [ ] **Step 3: Run repository checks available on Windows**

Run:

```powershell
git diff --check
rg -n ".{101}" src/capture src/flow src/main.cpp CMakeLists.txt README.md docs/design
rg -n "sudo iptables -I INPUT|sudo iptables -D INPUT|INPUT 규칙만" README.md docs/design
```

Expected: no whitespace errors, no changed line over 100 characters after formatting, and no stale manual-registration or INPUT-only statements.

- [ ] **Step 4: Record the unavailable local verification honestly**

Do not claim a successful Linux build on this Windows host. On Ubuntu, run:

```bash
cmake -S . -B build
cmake --build build -j
sudo ./build/ips
sudo iptables -S INPUT
sudo iptables -S OUTPUT
sudo iptables -S IPS_WITH_AI
```

Expected while running: one marked INPUT jump, one marked OUTPUT jump, an NFQUEUE rule with the configured queue and `--queue-bypass`, followed by the ownership RETURN marker. After SIGINT, the marked jumps and `IPS_WITH_AI` chain are absent.

- [ ] **Step 5: Execute the approved VM behavior matrix later**

On the Ubuntu VM, capture evidence for: remote SYN/SYN-ACK/ACK accumulating forward/backward counters; local SYN flow producing no Consumer record; inbound rule hit dropping the current packet; outbound always accepted; normal cleanup; force-kill bypass plus stale cleanup on restart; and rollback leaving no managed rules after an injected iptables failure.
