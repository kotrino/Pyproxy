import requests
import socks
import socket


def make_http_request_via_proxy(proxy_ip, proxy_port, username, password, use_encryption=True):
    """Выполняет запрос через HTTPS прокси с авторизацией или без нее."""
    try:
        protocol = "https" if use_encryption else "http"  # Выбор протокола в зависимости от шифрования
        if username and password:
            # Если логин и пароль указаны, используем их для авторизации
            proxies = {
                "http": f"http://{username}:{password}@{proxy_ip}:{proxy_port}",
                "https": f"https://{username}:{password}@{proxy_ip}:{proxy_port}"
            }
        else:
            # Если логина и пароля нет, подключаемся без авторизации
            proxies = {
                "http": f"http://{proxy_ip}:{proxy_port}",
                "https": f"https://{proxy_ip}:{proxy_port}"
            }
        # Выполняем тестовый запрос через указанный прокси
        url = "https://www.google.com" if use_encryption else "http://www.example.com"  # Разный URL для HTTP и HTTPS
        response = requests.get(url, proxies={protocol: proxies[protocol]}, timeout=10)

        # Проверка успешности запроса
        if response.status_code == 200:
            return f"HTTPS запрос выполнен успешно, статус: {response.status_code}"
        else:
            return f"Ошибка запроса через HTTPS прокси, статус: {response.status_code}"

    except requests.RequestException as e:
        return f"Ошибка запроса через HTTPS прокси: {e}"


def make_socks_request_via_proxy(proxy_ip, proxy_port, username, password):
    """Выполняет запрос через SOCKS прокси с авторизацией или без нее, с флагом шифрования (для информации)."""
    try:
        # Настраиваем SOCKS-прокси с учетом наличия логина и пароля
        if username and password:
            socks.set_default_proxy(socks.SOCKS5, proxy_ip, int(proxy_port), username=username, password=password)
        else:
            socks.set_default_proxy(socks.SOCKS5, proxy_ip, int(proxy_port))
        # Подменяем стандартный сокет на прокси-сокет
        socket.socket = socks.socksocket

        # Выполняем тестовый запрос (протокол в зависимости от шифрования, хотя SOCKS работает одинаково)
        url = "https://www.google.com" if use_encryption else "http://www.example.com"
        response = requests.get(url, timeout=10)

        # Проверка успешности запроса
        if response.status_code == 200:
            return f"Запрос через SOCKS выполнен успешно, шифрование: {'Включено' if use_encryption else 'Отключено'}, статус: {response.status_code}"
        else:
            return f"Ошибка запроса через SOCKS прокси, статус: {response.status_code}"

    except requests.RequestException as e:
        return f"Ошибка запроса через SOCKS прокси: {e}"
    except Exception as e:
        return f"Ошибка подключения через SOCKS прокси: {e}"
