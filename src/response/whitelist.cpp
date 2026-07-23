#include "response/whitelist.h"

#include <arpa/inet.h>

#include <glog/logging.h>

bool Whitelist::load(const std::vector<std::string>& ip_strings) {
    ips_.clear();
    bool ok = true;
    for (const std::string& s : ip_strings) {
        struct in_addr addr;
        // inet_pton은 네트워크 바이트 순서를 그대로 준다 — 파서 src_ip와 동일 순서.
        if (inet_pton(AF_INET, s.c_str(), &addr) == 1) {
            ips_.insert(addr.s_addr);
        } else {
            LOG(ERROR) << "화이트리스트 IP 형식 오류: " << s;
            ok = false;  // 오타 하나로 관리자 IP 보호가 무음 무력화되는 것을 막는다
        }
    }
    return ok;
}

bool Whitelist::is_whitelisted(uint32_t ip) const {
    return ips_.find(ip) != ips_.end();
}
