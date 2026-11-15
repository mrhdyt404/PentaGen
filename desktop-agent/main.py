import argparse
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any

from agent_client import (
    DesktopAgentClient,
    get_device_fingerprint,
    get_platform_info,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pentagen-desktop-agent")


def run_headless_agent(
    server_url: str | None = None,
    pairing_token: str | None = None,
    device_name: str | None = None,
    poll_once: bool = False,
    poll_loop: bool = False,
    interval: int = 5,
    config_file: str = "agent_config.json",
) -> int:
    """Execute desktop agent in CLI / headless mode."""
    client = DesktopAgentClient.load_config(config_file)

    if pairing_token and server_url:
        logger.info("Attempting pairing with %s...", server_url)
        try:
            res = client.pair(server_url, pairing_token, device_name)
            client.save_config(config_file)
            logger.info("Pairing successful! Assigned Agent ID: %s", client.agent_id)
        except Exception as exc:
            logger.error("Pairing failed: %s", exc)
            return 1

    if not client.is_paired:
        logger.warning("Agent is not paired. Run with --server <url> --pair <token> to establish pairing.")
        return 0

    logger.info("PentaGen Agent Node %s active (Org #%s)", client.agent_id, client.organization_id)

    def process_next_job() -> bool:
        try:
            job = client.poll_job()
            if not job:
                return False

            envelope_id = job.get("id")
            action = job.get("action")
            logger.info("Received envelope %s for action '%s'", envelope_id, action)

            is_valid, reason = client.verify_envelope(job)
            if not is_valid:
                logger.error("REJECTED envelope %s: %s", envelope_id, reason)
                return False

            logger.info("HMAC signature & policy verified for envelope %s. Executing...", envelope_id)
            results = client.execute_job(job)

            submit_resp = client.submit_results(envelope_id, results)
            logger.info("Execution complete. Results submitted: %s", submit_resp)
            return True
        except Exception as exc:
            logger.error("Error processing job: %s", exc)
            return False

    if poll_once:
        found = process_next_job()
        if not found:
            logger.info("No pending jobs available for this agent.")
        return 0

    if poll_loop:
        logger.info("Starting polling loop (interval: %ss). Press Ctrl+C to stop.", interval)
        try:
            while True:
                process_next_job()
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Polling loop stopped by user.")
            return 0

    return 0


def build_gui_app():
    """Launch PySide6 Graphical User Interface if available."""
    try:
        from PySide6.QtCore import QTimer, Qt
        from PySide6.QtGui import QColor, QFont
        from PySide6.QtWidgets import (
            QApplication,
            QCheckBox,
            QFormLayout,
            QGroupBox,
            QHBoxLayout,
            QLabel,
            QLineEdit,
            QMainWindow,
            QMessageBox,
            QPushButton,
            QTextEdit,
            QVBoxLayout,
            QWidget,
        )
    except ImportError:
        logger.warning("PySide6 is not installed. Falling back to headless mode.")
        run_headless_agent(poll_loop=False)
        return

    class DesktopAgentWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("PentaGen Desktop Agent v1.0")
            self.resize(780, 620)
            self.client = DesktopAgentClient.load_config("agent_config.json")

            self.poll_timer = QTimer(self)
            self.poll_timer.timeout.connect(self.on_poll_timer)

            self.init_ui()
            self.update_status_display()

        def init_ui(self):
            main_widget = QWidget()
            layout = QVBoxLayout(main_widget)
            layout.setSpacing(16)
            layout.setContentsMargins(20, 20, 20, 20)

            # Header
            header_layout = QHBoxLayout()
            title = QLabel("PentaGen Hybrid Desktop Agent")
            title.setStyleSheet("font-size: 20px; font-weight: bold; color: #38bdf8;")
            self.badge = QLabel("UNPAIRED")
            self.badge.setStyleSheet(
                "background: #334155; color: #cbd5e1; padding: 4px 10px; border-radius: 4px; font-weight: bold;"
            )
            header_layout.addWidget(title)
            header_layout.addStretch()
            header_layout.addWidget(self.badge)
            layout.addLayout(header_layout)

            # Pairing Form Group
            self.pairing_group = QGroupBox("Device Pairing")
            self.pairing_group.setStyleSheet("QGroupBox { font-weight: bold; color: #94a3b8; }")
            pair_layout = QFormLayout(self.pairing_group)

            self.server_input = QLineEdit(self.client.server_url or "http://127.0.0.1:8000")
            self.token_input = QLineEdit()
            self.token_input.setPlaceholderText("Enter one-time pairing token (pgp_...)")
            self.device_name_input = QLineEdit(self.client.device_name or "")

            pair_layout.addRow("Backend URL:", self.server_input)
            pair_layout.addRow("Pairing Token:", self.token_input)
            pair_layout.addRow("Device Label:", self.device_name_input)

            btn_box = QHBoxLayout()
            self.pair_btn = QPushButton("Pair Device")
            self.pair_btn.setStyleSheet(
                "background: #0284c7; color: white; padding: 6px 14px; font-weight: bold; border-radius: 4px;"
            )
            self.pair_btn.clicked.connect(self.handle_pair)
            self.reset_btn = QPushButton("Unpair / Reset")
            self.reset_btn.setStyleSheet("background: #dc2626; color: white; padding: 6px 14px; border-radius: 4px;")
            self.reset_btn.clicked.connect(self.handle_reset)
            btn_box.addWidget(self.pair_btn)
            btn_box.addWidget(self.reset_btn)
            btn_box.addStretch()
            pair_layout.addRow(btn_box)
            layout.addWidget(self.pairing_group)

            # Status & Details
            self.status_group = QGroupBox("Node Security Status")
            status_layout = QVBoxLayout(self.status_group)
            self.info_label = QLabel("No active credentials established.")
            self.info_label.setStyleSheet("color: #e2e8f0; font-family: monospace;")
            status_layout.addWidget(self.info_label)

            controls_box = QHBoxLayout()
            self.poll_now_btn = QPushButton("Poll Next Job")
            self.poll_now_btn.clicked.connect(self.handle_poll_once)
            self.auto_poll_check = QCheckBox("Enable Continuous Polling (5s)")
            self.auto_poll_check.stateChanged.connect(self.handle_toggle_auto_poll)
            controls_box.addWidget(self.poll_now_btn)
            controls_box.addWidget(self.auto_poll_check)
            controls_box.addStretch()
            status_layout.addLayout(controls_box)
            layout.addWidget(self.status_group)

            # Activity & Security Logs
            log_group = QGroupBox("Execution & Verification Trail")
            log_layout = QVBoxLayout(log_group)
            self.log_view = QTextEdit()
            self.log_view.setReadOnly(True)
            self.log_view.setStyleSheet(
                "background: #070d17; color: #a5f3fc; font-family: Consolas, monospace; font-size: 12px; border: 1px solid #1e293b;"
            )
            log_layout.addWidget(self.log_view)
            layout.addWidget(log_group)

            main_widget.setStyleSheet("background: #0b1424; color: #f8fafc;")
            self.setCentralWidget(main_widget)
            self.log_message("Desktop Agent initialized. Ready.")

        def log_message(self, msg: str):
            now = datetime.now(timezone.utc).strftime("%H:%M:%S")
            self.log_view.append(f"[{now}] {msg}")

        def update_status_display(self):
            if self.client.is_paired:
                self.badge.setText("PAIRED & READY")
                self.badge.setStyleSheet(
                    "background: #065f46; color: #6ee7b7; padding: 4px 10px; border-radius: 4px; font-weight: bold;"
                )
                self.info_label.setText(
                    f"Agent Node ID: {self.client.agent_id}\n"
                    f"Organization ID: {self.client.organization_id}\n"
                    f"Device Label: {self.client.device_name}\n"
                    f"Fingerprint: {get_device_fingerprint()[:16]}..."
                )
                self.poll_now_btn.setEnabled(True)
                self.auto_poll_check.setEnabled(True)
            else:
                self.badge.setText("UNPAIRED")
                self.badge.setStyleSheet(
                    "background: #334155; color: #cbd5e1; padding: 4px 10px; border-radius: 4px; font-weight: bold;"
                )
                self.info_label.setText("Device is not paired to any PentaGen backend orchestrator.")
                self.poll_now_btn.setEnabled(False)
                self.auto_poll_check.setEnabled(False)
                self.auto_poll_check.setChecked(False)

        def handle_pair(self):
            server = self.server_input.text().strip()
            token = self.token_input.text().strip()
            dev_name = self.device_name_input.text().strip()

            if not server or not token:
                QMessageBox.warning(self, "Input Error", "Please provide both backend URL and pairing token.")
                return

            self.log_message(f"Connecting to {server} to pair device...")
            try:
                data = self.client.pair(server, token, dev_name)
                self.client.save_config("agent_config.json")
                self.token_input.clear()
                self.log_message(f"Successfully paired! Node ID: {self.client.agent_id}")
                self.update_status_display()
                QMessageBox.information(self, "Success", "Desktop Agent paired successfully.")
            except Exception as exc:
                self.log_message(f"Pairing failure: {exc}")
                QMessageBox.critical(self, "Pairing Failed", str(exc))

        def handle_reset(self):
            confirm = QMessageBox.question(
                self,
                "Confirm Reset",
                "Are you sure you want to clear stored pairing credentials?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if confirm == QMessageBox.Yes:
                self.client = DesktopAgentClient()
                if os.path.exists("agent_config.json"):
                    os.remove("agent_config.json")
                self.update_status_display()
                self.log_message("Agent credentials cleared.")

        def handle_poll_once(self):
            if not self.client.is_paired:
                return
            self.log_message("Polling backend for signed job envelopes...")
            try:
                job = self.client.poll_job()
                if not job:
                    self.log_message("No pending jobs found.")
                    return

                envelope_id = job.get("id")
                action = job.get("action")
                self.log_message(f"Dispatched envelope: {envelope_id} (action: {action})")

                is_valid, reason = self.client.verify_envelope(job)
                if not is_valid:
                    self.log_message(f"SECURITY ALERT: Verification failed for {envelope_id}: {reason}")
                    return

                self.log_message(f"HMAC verified. Executing {action} locally...")
                results = self.client.execute_job(job)

                submit_resp = self.client.submit_results(envelope_id, results)
                self.log_message(f"Results submitted successfully. Envelope {envelope_id} completed.")
            except Exception as exc:
                self.log_message(f"Error during job processing: {exc}")

        def handle_toggle_auto_poll(self, state):
            if state == 2:  # Checked
                self.poll_timer.start(5000)
                self.log_message("Auto-polling enabled (5s).")
            else:
                self.poll_timer.stop()
                self.log_message("Auto-polling disabled.")

        def on_poll_timer(self):
            self.handle_poll_once()

    app = QApplication(sys.argv)
    window = DesktopAgentWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PentaGen Hybrid Desktop Agent")
    parser.add_argument("--headless", action="store_true", help="Run without graphical user interface")
    parser.add_argument("--server", type=str, help="PentaGen backend server URL")
    parser.add_argument("--pair", type=str, help="One-time pairing token")
    parser.add_argument("--device-name", type=str, help="Friendly label for this desktop device")
    parser.add_argument("--poll-once", action="store_true", help="Poll once for pending job and execute")
    parser.add_argument("--poll-loop", action="store_true", help="Run continuous polling loop")
    parser.add_argument("--interval", type=int, default=5, help="Polling interval in seconds")
    parser.add_argument("--config", type=str, default="agent_config.json", help="Path to credentials config")

    args = parser.parse_args()

    if args.headless or args.pair or args.poll_once or args.poll_loop:
        exit_code = run_headless_agent(
            server_url=args.server,
            pairing_token=args.pair,
            device_name=args.device_name,
            poll_once=args.poll_once,
            poll_loop=args.poll_loop,
            interval=args.interval,
            config_file=args.config,
        )
        sys.exit(exit_code)
    else:
        build_gui_app()
