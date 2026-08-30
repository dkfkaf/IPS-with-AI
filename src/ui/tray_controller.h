#ifndef IPS_SRC_UI_TRAY_CONTROLLER_H_
#define IPS_SRC_UI_TRAY_CONTROLLER_H_

#include <functional>
#include <memory>
#include <string>

#include <QObject>

#include "ai/ai_types.h"

class QMenu;
class QSystemTrayIcon;

class TrayController final : public QObject {
 public:
    using ActionHandler = std::function<void()>;

    TrayController(ActionHandler status_handler, ActionHandler exit_handler,
                   QObject* parent = nullptr);
    ~TrayController() override;

    void set_ai_state(AiState state, const std::string& detail);
    void show_ai_block(const AiBlockEvent& event);
    void show_ai_offline(const std::string& reason);
    void show_status(const std::string& text);
    bool is_available() const;

 private:
    ActionHandler status_handler_;
    ActionHandler exit_handler_;
    std::unique_ptr<QMenu> menu_;
    std::unique_ptr<QSystemTrayIcon> tray_icon_;
    bool available_ = false;
    bool offline_shown_ = false;
};

#endif  // IPS_SRC_UI_TRAY_CONTROLLER_H_
