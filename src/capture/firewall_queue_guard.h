#ifndef IPS_SRC_CAPTURE_FIREWALL_QUEUE_GUARD_H_
#define IPS_SRC_CAPTURE_FIREWALL_QUEUE_GUARD_H_

#include <cstdint>

// INPUT·OUTPUT을 같은 NFQUEUE로 보내는 iptables 규칙의 수명주기를 관리한다.
class FirewallQueueGuard {
 public:
    explicit FirewallQueueGuard(uint16_t queue_num);
    ~FirewallQueueGuard();

    FirewallQueueGuard(const FirewallQueueGuard&) = delete;
    FirewallQueueGuard& operator=(const FirewallQueueGuard&) = delete;

    bool install();
    bool uninstall();

 private:
    bool remove_chain(bool require_owner_marker);
    bool remove_owned_chain();
    bool remove_current_chain();

    uint16_t queue_num_;
    bool installed_ = false;
    bool owns_chain_ = false;
};

#endif  // IPS_SRC_CAPTURE_FIREWALL_QUEUE_GUARD_H_
