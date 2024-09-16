import json
import re

import psutil
import os.path

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QRadioButton, QButtonGroup, QListWidget, QHBoxLayout, QMessageBox, QComboBox, QCheckBox, QInputDialog, QSpacerItem,
    QSizePolicy
)
from PySide6.QtCore import Qt, QTimer

from protocols import make_http_request_via_proxy, make_socks_request_via_proxy


class ProxyApp(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('PyProxy')

        self.presets_file = "proxy_presets.json"
        self.presets = self.load_presets()

        self.layout_left = QVBoxLayout()
        self.layout_left.setAlignment(Qt.AlignTop)

        self.left_container = QWidget()
        self.left_container.setLayout(self.layout_left)
        self.left_container.setFixedWidth(250)

        self.layout_middle = QVBoxLayout()
        self.layout_buttons = QVBoxLayout()
        self.layout_buttons.setAlignment(Qt.AlignCenter)
        self.layout_right = QVBoxLayout()
        self.layout_right.setAlignment(Qt.AlignTop)
        self.layout = QHBoxLayout()
        self.layout.setAlignment(Qt.AlignCenter)

        self.preset_label_layout = QHBoxLayout()
        self.preset_label = QLabel("Пресет:")
        self.preset_combo = QComboBox()
        self.preset_combo.addItems(self.presets.keys())
        self.preset_combo.currentTextChanged.connect(lambda preset_name: self.load_preset_in(preset_name))

        self.proxy_ip_label = QLabel("IP прокси:")
        self.proxy_ip_input = QLineEdit()

        self.proxy_port_label = QLabel("Порт прокси:")
        self.proxy_port_input = QLineEdit()

        # Чекбокс для подключения без логина и пароля
        self.no_auth_checkbox = QCheckBox("Подключиться без логина и пароля")
        self.no_auth_checkbox.stateChanged.connect(self.toggle_auth_fields)

        self.proxy_user_label = QLabel("Логин (если нужен):")
        self.proxy_user_input = QLineEdit()

        self.proxy_pass_label = QLabel("Пароль (если нужен):")
        self.proxy_pass_input = QLineEdit()
        self.proxy_pass_input.setEchoMode(QLineEdit.Password)

        self.proxy_type_label = QLabel("Тип прокси:")
        self.https_radio = QRadioButton("HTTPS")
        self.socks_radio = QRadioButton("SOCKS")
        self.proxy_type_group = QButtonGroup()
        self.proxy_type_group.addButton(self.https_radio)
        self.proxy_type_group.addButton(self.socks_radio)
        self.https_radio.setChecked(True)
        self.proxy_string_label = QLabel("Вставьте строку прокси:")
        self.proxy_string_input = QLineEdit()
        self.parse_button = QPushButton("Распознать прокси")
        self.parse_button.clicked.connect(lambda: self.parse_proxy_string(self.proxy_string_input.text()))

        self.active_apps_label = QLabel("Активные приложения")
        self.active_apps_list = QListWidget()
        self.active_apps_list.setSelectionMode(QListWidget.MultiSelection)

        self.selected_apps_label = QLabel("Выбранные приложения")
        self.selected_apps_list = QListWidget()
        self.selected_apps_list.setSelectionMode(QListWidget.MultiSelection)

        self.manual_app_input = QLineEdit()
        self.manual_app_input.setPlaceholderText("Введите имя приложения")
        self.add_manual_app_button = QPushButton("Добавить приложение")
        self.add_manual_app_button.clicked.connect(self.add_manual_app)

        self.add_app_button = QPushButton("-> Добавить")
        self.add_app_button.clicked.connect(self.add_app_to_selected)

        self.remove_app_button = QPushButton("<- Удалить")
        self.remove_app_button.clicked.connect(self.remove_app_from_selected)

        # Кнопка обновления списка приложений
        self.refresh_button = QPushButton("Обновить список приложений")
        self.refresh_button.clicked.connect(self.load_active_apps)

        self.apply_button = QPushButton("Применить")
        self.apply_button.clicked.connect(self.apply_settings)

        # Кнопка для сохранения пресета
        self.save_preset_button = QPushButton("Сохранить как пресет")
        self.save_preset_button.clicked.connect(self.save_preset)

        # Кнопка для удаления пресета
        self.delete_preset_button = QPushButton("Del")
        self.delete_preset_button.clicked.connect(self.delete_preset)

        # Размещаем элементы интерфейса в основном layout
        self.preset_label_layout.addWidget(self.preset_label, stretch=1)
        self.preset_label_layout.addWidget(self.delete_preset_button)
        self.layout_left.addLayout(self.preset_label_layout)
        self.layout_left.addWidget(self.preset_combo)
        self.layout_left.addWidget(self.save_preset_button)

        self.layout_left.addWidget(self.proxy_ip_label)
        self.layout_left.addWidget(self.proxy_ip_input)
        self.layout_left.addWidget(self.proxy_port_label)
        self.layout_left.addWidget(self.proxy_port_input)
        self.layout_left.addWidget(self.no_auth_checkbox)
        self.layout_left.addWidget(self.proxy_user_label)
        self.layout_left.addWidget(self.proxy_user_input)
        self.layout_left.addWidget(self.proxy_pass_label)
        self.layout_left.addWidget(self.proxy_pass_input)

        self.layout_left.addWidget(self.proxy_type_label)
        self.layout_left.addWidget(self.https_radio)
        self.layout_left.addWidget(self.socks_radio)
        self.layout_left.addWidget(self.proxy_string_label)
        self.layout_left.addWidget(self.proxy_string_input)
        self.layout_left.addWidget(self.parse_button)

        self.layout_middle.addWidget(self.active_apps_label)
        self.layout_middle.addWidget(self.active_apps_list, stretch=1)
        self.layout_middle.addWidget(self.refresh_button)
        self.layout_middle.addWidget(self.apply_button)

        self.layout_buttons.addWidget(self.add_app_button)
        self.layout_buttons.addWidget(self.remove_app_button)

        self.layout_right.addWidget(self.selected_apps_label)
        self.layout_right.addWidget(self.selected_apps_list, stretch=1)
        self.layout_right.addWidget(self.manual_app_input)
        self.layout_right.addWidget(self.add_manual_app_button)

        self.layout.addWidget(self.left_container)
        self.layout.addLayout(self.layout_middle)
        self.layout.addLayout(self.layout_buttons)
        self.layout.addLayout(self.layout_right)
        self.setLayout(self.layout)

        self.auto_refresh_interval = 10000
        self.timer = QTimer()
        self.timer.timeout.connect(self.load_active_apps)
        self.timer.start(self.auto_refresh_interval)

        # Загружаем активные приложения при старте
        self.load_active_apps()

        if self.presets:
            first_preset = next(iter(self.presets))  # Получаем первый доступный пресет
            self.preset_combo.setCurrentText(first_preset)  # Устанавливаем его в комбобоксе
            self.load_preset_in(first_preset)  # Загружаем пресет

    @staticmethod
    def get_active_apps():
        """
        Получает список активных приложений с использованием psutil
        """
        active_apps = {}
        system_processes = ['smss.exe', 'csrss.exe', 'svchost.exe', 'wininit.exe', 'services.exe',
                            'lsass.exe', 'system', 'idle']
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                proc_info = proc.info
                # Фильтруем системные процессы, процессы без имени и с PID меньше 100
                if proc_info['name'] and proc_info['pid'] > 100 and proc_info['username'] != 'SYSTEM':
                    if proc_info['name'].lower() not in [name.lower() for name in system_processes]:
                        if proc_info['name'] not in active_apps:
                            active_apps[proc_info['name']] = proc_info['pid']
                        else:
                            # Оставляем только процесс с наименьшим PID (главный процесс)
                            if proc_info['pid'] < active_apps[proc_info['name']]:
                                active_apps[proc_info['name']] = proc_info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

        return sorted(active_apps.keys())

    def parse_proxy_string(self, proxy_string):
        """
        Парсит строку с данными прокси и заполняет соответствующие поля.
        """
        # Регулярное выражение для парсинга строки прокси
        proxy_pattern = re.compile(
            r'(?P<type>socks5|https)?://'
            r'(?:(?P<login>[^:]+):(?P<password>[^@]+)@)?'  # Опциональные логин и пароль
            r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'  # IP-адрес
            r':(?P<port>\d{2,5})'  # Порт
        )

        match = proxy_pattern.match(proxy_string)

        if match:
            proxy_info = match.groupdict()
            self.proxy_ip_input.setText(proxy_info['ip'])
            self.proxy_port_input.setText(proxy_info['port'])

            if proxy_info['login'] and proxy_info['password']:
                self.proxy_user_input.setText(proxy_info['login'])
                self.proxy_pass_input.setText(proxy_info['password'])
                self.no_auth_checkbox.setChecked(False)
            else:
                self.no_auth_checkbox.setChecked(True)
                self.proxy_user_input.clear()
                self.proxy_pass_input.clear()

            # Определяем тип прокси
            if proxy_info['type'] == 'socks5':
                self.socks_radio.setChecked(True)
            else:
                self.https_radio.setChecked(True)

            QMessageBox.information(self, "Успех", "Данные прокси успешно распознаны и применены.")
        else:
            # Если строка содержит только IP и порт, пытаемся парсить их напрямую
            simple_proxy_pattern = re.compile(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{2,5})')
            simple_match = simple_proxy_pattern.match(proxy_string)

            if simple_match:
                proxy_info = simple_match.groupdict()

                # Заполняем только IP и порт, остальные поля очищаем
                self.proxy_ip_input.setText(proxy_info['ip'])
                self.proxy_port_input.setText(proxy_info['port'])
                self.no_auth_checkbox.setChecked(True)
                self.proxy_user_input.clear()
                self.proxy_pass_input.clear()
                self.https_radio.setChecked(True)  # По умолчанию HTTPS

                QMessageBox.information(self, "Успех", "Данные IP и порт успешно распознаны и применены.")
            else:
                QMessageBox.critical(self, "Ошибка", "Не удалось распознать данные прокси.")

    def add_manual_app(self):
        """
        Добавляет приложение вручную в список активных приложений
        """
        app_name = self.manual_app_input.text().strip()
        if app_name and not any(
                app_name == self.active_apps_list.item(i).text() for i in range(self.active_apps_list.count())):
            self.active_apps_list.addItem(app_name)
        self.manual_app_input.clear()

    def load_active_apps(self):
        """
        Загружает активные приложения из системы
        """
        # Сохраняем список выбранных приложений
        selected_apps = [self.selected_apps_list.item(i).text() for i in range(self.selected_apps_list.count())]

        # Обновляем список активных приложений
        self.active_apps_list.clear()
        active_apps = self.get_active_apps()

        # Добавляем только те активные приложения, которые еще не выбраны
        for app in active_apps:
            if app not in selected_apps:
                self.active_apps_list.addItem(app)

        if not active_apps:
            self.active_apps_list.addItem("Нет активных приложений")

    def add_app_to_selected(self):
        """
        Добавляет выбранные в левом списке приложения в правый (выбранные)
        """
        selected_items = self.active_apps_list.selectedItems()
        for item in selected_items:
            app_name = item.text()
            if not any(
                    app_name == self.selected_apps_list.item(i).text() for i in range(self.selected_apps_list.count())):
                self.selected_apps_list.addItem(app_name)

    def remove_app_from_selected(self):
        """
        Удаляет выбранные в правом списке приложения
        """
        selected_items = self.selected_apps_list.selectedItems()
        for item in selected_items:
            self.selected_apps_list.takeItem(self.selected_apps_list.row(item))

    def toggle_auth_fields(self):
        """
        Включает или отключает поля логина и пароля
        """
        state = self.no_auth_checkbox.isChecked()
        self.proxy_user_label.setEnabled(not state)
        self.proxy_user_input.setEnabled(not state)
        self.proxy_pass_label.setEnabled(not state)
        self.proxy_pass_input.setEnabled(not state)

    def load_presets(self):
        """
        Загружает настройки из файла
        """
        if os.path.exists(self.presets_file):
            with open(self.presets_file, 'r') as f:
                return json.load(f)
        return {}

    def save_presets(self):
        """
        Сохраняет текущие настройки в файл
        """
        with open(self.presets_file, 'w') as f:
            json.dump(self.presets, f, indent=4)

    def load_preset_in(self, preset_name):
        """
        Загружает выбранный пресет в поля
        """
        if preset_name in self.presets:
            preset = self.presets[preset_name]
            self.proxy_ip_input.setText(preset.get('ip', ''))
            self.proxy_port_input.setText(preset.get('port', ''))
            self.proxy_user_input.setText(preset.get('user', ''))
            self.proxy_pass_input.setText(preset.get('password', ''))

            if preset['type'] == 'HTTPS':
                self.https_radio.setChecked(True)
            else:
                self.socks_radio.setChecked(True)

            # Загружаем список приложений в список
            self.active_apps_list.clear()
            active_apps = self.get_active_apps()
            self.active_apps_list.addItems(active_apps)

            if 'apps' in preset:
                for i in range(self.active_apps_list.count()):
                    item = self.active_apps_list.item(i)
                    if item.text() in preset['apps']:
                        item.setSelected(True)

    def save_preset(self):
        """
        Сохраняет текущие настройки в пресет
        """
        preset_name, ok = QInputDialog.getText(self, "Сохранить пресет", "Введите имя пресета:")
        if ok and preset_name:
            selected_apps = [item.text() for item in self.active_apps_list.selectedItems()]
            self.presets[preset_name] = {
                'ip': self.proxy_ip_input.text(),
                'port': self.proxy_port_input.text(),
                'user': self.proxy_user_input.text(),
                'password': self.proxy_pass_input.text(),
                'type': 'HTTPS' if self.https_radio.isChecked() else 'SOCKS',
                'apps': selected_apps  # Сохраняем выбранные приложения
            }
            self.save_presets()
            self.preset_combo.addItem(preset_name)
            QMessageBox.information(self, "Успех", f"Пресет '{preset_name}' сохранен.")

    def delete_preset(self):
        """
        Удаляет выбранный пресет
        """
        preset_name = self.preset_combo.currentText()
        if preset_name in self.presets:
            del self.presets[preset_name]
            self.save_presets()
            self.preset_combo.removeItem(self.preset_combo.currentIndex())
            QMessageBox.information(self, "Успех", f"Пресет '{preset_name}' удален.")

    def apply_settings(self):
        """
        Применяет текущие настройки к приложениям
        """
        proxy_ip = self.proxy_ip_input.text()
        proxy_port = self.proxy_port_input.text()

        if not self.no_auth_checkbox.isChecked():
            proxy_user = self.proxy_user_input.text()
            proxy_pass = self.proxy_pass_input.text()
        else:
            proxy_user = proxy_pass = None

        proxy_type = "HTTPS" if self.https_radio.isChecked() else "SOCKS"
        selected_apps = [item.text() for item in self.active_apps_list.selectedItems()]

        if not proxy_ip or not proxy_port:
            QMessageBox.critical(self, "Ошибка", "Не заполнены обязательные поля IP и порт прокси")
            return

        connection_info = f"Подключение через {proxy_type} прокси {proxy_ip}:{proxy_port}"
        if proxy_user and proxy_pass:
            connection_info += f" с логином {proxy_user}"
        else:
            connection_info += " без авторизации"

        results = []
        for app in selected_apps:
            if proxy_type == "HTTPS":
                result = make_http_request_via_proxy(proxy_ip, proxy_port, proxy_user, proxy_pass)
            else:
                result = make_socks_request_via_proxy(proxy_ip, proxy_port, proxy_user, proxy_pass)
            results.append(f"{app}: {result}")

        QMessageBox.information(self, "Успех", f"Настройки применены:"
                                               f"\n{connection_info}"
                                               f"\nПриложения: {', '.join(selected_apps)}")


if __name__ == "__main__":
    app = QApplication([])
    window = ProxyApp()
    window.show()
    app.exec()