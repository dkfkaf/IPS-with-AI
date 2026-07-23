#ifndef IPS_SRC_DETECT_RULE_H_
#define IPS_SRC_DETECT_RULE_H_

#include "flow/flow.h"

// 탐지 규칙 인터페이스 (Strategy). 새 규칙 = 자식 클래스 추가 + 등록 한 줄 (개방-폐쇄).
// 2단계 규칙 2종은 출발지 통계만 읽으므로 인자는 SourceStats뿐이다.
class Rule {
 public:
    virtual ~Rule() = default;
    virtual const char* name() const = 0;                       // 차단 로그용 규칙 이름
    virtual bool is_match(const SourceStats& stats) const = 0;  // 걸리면 true
};

#endif  // IPS_SRC_DETECT_RULE_H_
