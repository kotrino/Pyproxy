import psutil
import time
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget


class SpeedMonitor(QWidget):
    def __init__(self):
        super().__init__()

        # Создаем метки для отображения скорости
        self.download_speed_label = QLabel("Скорость загрузки: 0 KB/s")
        self.upload_speed_label = QLabel("Скорость выгрузки: 0 KB/s")

        # Лейаут для отображения данных
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.download_speed_label)
        self.layout.addWidget(self.upload_speed_label)
        self.setLayout(self.layout)

        # Переменные для хранения предыдущих данных
        self.prev_counters = psutil.net_io_counters()
        self.download_speed = 0
        self.upload_speed = 0

        # Таймер для обновления скорости
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_speed)
        self.timer.start(1000)  # Обновляем каждую секунду

    def update_speed(self):
        # Получаем текущие данные о сети
        current_counters = psutil.net_io_counters()

        # Вычисляем количество переданных и полученных байт за последний интервал
        download_diff = current_counters.bytes_recv - self.prev_counters.bytes_recv
        upload_diff = current_counters.bytes_sent - self.prev_counters.bytes_sent

        # Расчет скорости передачи данных (в байтах/секунду)
        download_speed = download_diff / 1.0  # делим на 1 секунду
        upload_speed = upload_diff / 1.0

        # Обновляем переменные для плавной анимации через экспоненциальное сглаживание
        smoothing_factor = 0.1
        self.download_speed = (1 - smoothing_factor) * self.download_speed + smoothing_factor * download_speed
        self.upload_speed = (1 - smoothing_factor) * self.upload_speed + smoothing_factor * upload_speed

        # Обновляем метки с текущими скоростями
        self.download_speed_label.setText(f"Скорость загрузки: {self.format_speed(self.download_speed)}")
        self.upload_speed_label.setText(f"Скорость выгрузки: {self.format_speed(self.upload_speed)}")

        # Сохраняем текущие данные как предыдущие для следующего интервала
        self.prev_counters = current_counters

    def format_speed(self, speed):
        """
        Форматирует скорость в удобный для чтения формат (KB/s, MB/s, и т.д.)
        """
        if speed < 1024:
            return f"{speed:.2f} B/s"
        elif speed < 1024 ** 2:
            return f"{speed / 1024:.2f} KB/s"
        else:
            return f"{speed / 1024 ** 2:.2f} MB/s"


if __name__ == "__main__":
    import sys
    from PySide6.QtWidgets import QApplication

    app = QApplication(sys.argv)
    window = SpeedMonitor()
    window.show()
    sys.exit(app.exec())
