#include "capture/firewall_queue_guard.h"

#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <string>
#include <vector>

#include <glog/logging.h>

namespace {

constexpr char IPTABLES_PATH[] = "/usr/sbin/iptables";
constexpr char CHAIN_NAME[] = "IPS_WITH_AI";
constexpr char JUMP_COMMENT[] = "ips-with-ai-managed";
constexpr char OWNER_COMMENT[] = "ips-with-ai-owned";

int run_iptables(const std::vector<std::string>& arguments) {
    std::vector<std::string> command;
    command.reserve(arguments.size() + 2);
    command.emplace_back(IPTABLES_PATH);
    command.emplace_back("-w");
    command.insert(command.end(), arguments.begin(), arguments.end());

    std::vector<char*> argv;
    argv.reserve(command.size() + 1);
    for (std::string& argument : command) {
        argv.push_back(argument.data());
    }
    argv.push_back(nullptr);

    const pid_t child = fork();
    if (child < 0) {
        LOG(ERROR) << "iptables fork 실패";
        return -1;
    }
    if (child == 0) {
        execv(IPTABLES_PATH, argv.data());
        _exit(127);
    }

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            LOG(ERROR) << "iptables waitpid 실패";
            return -1;
        }
    }
    if (!WIFEXITED(status)) {
        LOG(ERROR) << "iptables 프로세스 비정상 종료";
        return -1;
    }
    return WEXITSTATUS(status);
}

std::vector<std::string> jump_rule(const char* operation, const char* builtin_chain) {
    return {operation, builtin_chain, "-m", "comment", "--comment", JUMP_COMMENT,
            "-j", CHAIN_NAME};
}

bool remove_managed_jumps(const char* builtin_chain) {
    while (true) {
        const int check_status = run_iptables(jump_rule("-C", builtin_chain));
        if (check_status == 1) {
            return true;
        }
        if (check_status != 0) {
            LOG(ERROR) << builtin_chain << " 관리 jump 확인 실패";
            return false;
        }
        if (run_iptables(jump_rule("-D", builtin_chain)) != 0) {
            LOG(ERROR) << builtin_chain << " 관리 jump 제거 실패";
            return false;
        }
    }
}

}  // namespace

FirewallQueueGuard::FirewallQueueGuard(uint16_t queue_num) : queue_num_(queue_num) {}

FirewallQueueGuard::~FirewallQueueGuard() {
    if (owns_chain_ && !remove_current_chain()) {
        LOG(ERROR) << "iptables 관리 규칙 소멸자 정리 실패";
    }
}

bool FirewallQueueGuard::remove_chain(bool require_owner_marker) {
    const int chain_status = run_iptables({"-n", "-L", CHAIN_NAME});
    if (chain_status == 1) {
        return true;
    }
    if (chain_status != 0) {
        LOG(ERROR) << "iptables 전용 체인 확인 실패";
        return false;
    }

    if (require_owner_marker) {
        const int owner_status = run_iptables({"-C", CHAIN_NAME, "-m", "comment",
                                               "--comment", OWNER_COMMENT, "-j", "RETURN"});
        if (owner_status == 1) {
            LOG(ERROR) << CHAIN_NAME << " 체인이 다른 사용자 소유라 시작을 중단";
            return false;
        }
        if (owner_status != 0) {
            LOG(ERROR) << "iptables 전용 체인 소유권 확인 실패";
            return false;
        }
    }

    if (!remove_managed_jumps("INPUT") || !remove_managed_jumps("OUTPUT")) {
        return false;
    }
    if (run_iptables({"-F", CHAIN_NAME}) != 0) {
        LOG(ERROR) << "iptables 전용 체인 비우기 실패";
        return false;
    }
    if (run_iptables({"-X", CHAIN_NAME}) == 0) {
        return true;
    }

    LOG(ERROR) << "iptables 전용 체인 제거 실패";
    const int remaining_status = run_iptables({"-n", "-L", CHAIN_NAME});
    if (remaining_status == 1) {
        return true;
    }
    if (remaining_status != 0 ||
        run_iptables({"-A", CHAIN_NAME, "-m", "comment", "--comment", OWNER_COMMENT,
                      "-j", "RETURN"}) != 0) {
        LOG(ERROR) << "iptables 전용 체인 소유권 표시 복원 실패";
        return false;
    }
    LOG(WARNING) << "iptables 전용 체인은 남았지만 소유권 표시를 복원함";
    return false;
}

bool FirewallQueueGuard::remove_owned_chain() { return remove_chain(true); }

bool FirewallQueueGuard::remove_current_chain() {
    if (!remove_chain(false)) {
        return false;
    }
    owns_chain_ = false;
    installed_ = false;
    return true;
}

bool FirewallQueueGuard::install() {
    if (installed_) {
        return true;
    }
    if (owns_chain_ && !remove_current_chain()) {
        return false;
    }
    if (!remove_owned_chain()) {
        return false;
    }

    auto rollback = [&]() {
        if (!remove_current_chain()) {
            LOG(ERROR) << "iptables 신규 규칙 롤백 미완료 — 소멸자에서 재시도";
        }
    };

    if (run_iptables({"-N", CHAIN_NAME}) != 0) {
        LOG(ERROR) << "iptables 전용 체인 생성 실패";
        return false;
    }
    owns_chain_ = true;

    const std::string queue_num = std::to_string(queue_num_);
    if (run_iptables({"-A", CHAIN_NAME, "-j", "NFQUEUE", "--queue-num", queue_num,
                      "--queue-bypass"}) != 0 ||
        run_iptables({"-A", CHAIN_NAME, "-m", "comment", "--comment", OWNER_COMMENT,
                      "-j", "RETURN"}) != 0) {
        LOG(ERROR) << "iptables 전용 체인 규칙 생성 실패";
        rollback();
        return false;
    }

    if (run_iptables({"-I", "INPUT", "1", "-m", "comment", "--comment", JUMP_COMMENT,
                      "-j", CHAIN_NAME}) != 0) {
        LOG(ERROR) << "iptables INPUT jump 생성 실패";
        rollback();
        return false;
    }
    if (run_iptables({"-I", "OUTPUT", "1", "-m", "comment", "--comment", JUMP_COMMENT,
                      "-j", CHAIN_NAME}) != 0) {
        LOG(ERROR) << "iptables OUTPUT jump 생성 실패";
        rollback();
        return false;
    }

    installed_ = true;
    LOG(INFO) << "iptables INPUT·OUTPUT 자동 등록 완료 (NFQUEUE " << queue_num_ << ')';
    return true;
}

bool FirewallQueueGuard::uninstall() {
    if (!owns_chain_) {
        return true;
    }
    if (!remove_current_chain()) {
        return false;
    }
    LOG(INFO) << "iptables 관리 규칙 제거 완료";
    return true;
}
