#include "ui/tray_controller.h"

#include <exception>
#include <utility>

#include <QAction>
#include <QColor>
#include <QIcon>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPixmap>
#include <QString>
#include <QSystemTrayIcon>

#include <glog/logging.h>

#include "common/five_tuple.h"

namespace {

QIcon make_status_icon(const QColor& color) {
    QPixmap pixmap(16, 16);
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setPen(Qt::NoPen);
    painter.setBrush(color);
    painter.drawEllipse(2, 2, 12, 12);
    return QIcon(pixmap);
}

QColor state_color(AiState state) {
    switch (state) {
        case AiState::ONLINE:
            return QColor(46, 204, 113);
        case AiState::DISABLED:
        case AiState::OFFLINE:
            return QColor(241, 196, 15);
        case AiState::STARTING:
        case AiState::RESTART_WAIT:
        case AiState::STOPPING:
            return QColor(128, 128, 128);
    }
    return QColor(128, 128, 128);
}

}  // namespace

TrayController::TrayController(ActionHandler status_handler, ActionHandler exit_handler,
                               QObject* parent)
    : QObject(parent),
      status_handler_(std::move(status_handler)),
      exit_handler_(std::move(exit_handler)) {
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        LOG(WARNING) << "시스템 트레이를 사용할 수 없음 — 알림 UI 비활성화";
        return;
    }

    menu_ = std::make_unique<QMenu>();
    QAction* status_action = menu_->addAction("상태 보기");
    QAction* exit_action = menu_->addAction("종료");
    connect(status_action, &QAction::triggered, this, [this] {
        try {
            if (status_handler_) {
                status_handler_();
            }
        } catch (const std::exception& error) {
            LOG(ERROR) << "tray status handler 오류: " << error.what();
        }
    });
    connect(exit_action, &QAction::triggered, this, [this] {
        try {
            if (exit_handler_) {
                exit_handler_();
            }
        } catch (const std::exception& error) {
            LOG(ERROR) << "tray exit handler 오류: " << error.what();
        }
    });

    tray_icon_ = std::make_unique<QSystemTrayIcon>();
    tray_icon_->setContextMenu(menu_.get());
    tray_icon_->setIcon(make_status_icon(state_color(AiState::STARTING)));
    tray_icon_->setToolTip("IPS - AI 시작 전");
    tray_icon_->show();
    available_ = true;
}

TrayController::~TrayController() {
    if (tray_icon_) {
        tray_icon_->hide();
    }
}

void TrayController::set_ai_state(AiState state, const std::string& detail) {
    if (!available_) {
        return;
    }
    if (state == AiState::ONLINE) {
        offline_shown_ = false;
    }
    tray_icon_->setIcon(make_status_icon(state_color(state)));
    tray_icon_->setToolTip("IPS - " + QString::fromStdString(detail));
}

void TrayController::show_ai_block(const AiBlockEvent& event) {
    if (!available_) {
        return;
    }
    const QString body =
        QString::fromStdString(ip_to_string(event.source_ip)) +
        "의 종료된 Flow를 이상으로 판정했습니다.\n이후 수신 패킷을 " +
        QString::number(event.ttl_seconds) + "초 동안 차단합니다.\nscore=" +
        QString::number(event.score, 'g', 6) + ", threshold=" +
        QString::number(event.threshold, 'g', 6);
    tray_icon_->showMessage("AI 이상 Flow 탐지", body, QSystemTrayIcon::Warning, 5000);
}

void TrayController::show_ai_offline(const std::string& reason) {
    if (!available_ || offline_shown_) {
        return;
    }
    offline_shown_ = true;
    tray_icon_->showMessage("AI 오프라인", QString::fromStdString(reason),
                            QSystemTrayIcon::Warning, 5000);
}

void TrayController::show_status(const std::string& text) {
    if (!available_) {
        return;
    }
    QMessageBox::information(nullptr, "IPS 상태", QString::fromStdString(text));
}

bool TrayController::is_available() const {
    return available_;
}
