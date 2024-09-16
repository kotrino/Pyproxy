import requests
import socks
import socket


def make_http_request_via_proxy(proxy_ip, proxy_port, username, password):
    """Выполняет запрос через HTTPS прокси с авторизацией или без нее."""
    try:
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
        response = requests.get("https://www.google.com", proxies=proxies, timeout=10)
        # Проверка успешности запроса
        if response.status_code == 200:
            return f"HTTPS запрос выполнен успешно, статус: {response.status_code}"
        else:
            return f"Ошибка запроса через HTTPS прокси, статус: {response.status_code}"

    except requests.RequestException as e:
        return f"Ошибка запроса через HTTPS прокси: {e}"


def make_socks_request_via_proxy(proxy_ip, proxy_port, username, password):
    """Выполняет запрос через SOCKS прокси с авторизацией или без нее."""
    try:
        # Настраиваем SOCKS-прокси с учетом наличия логина и пароля
        if username and password:
            socks.set_default_proxy(socks.SOCKS5, proxy_ip, int(proxy_port), username=username, password=password)
        else:
            socks.set_default_proxy(socks.SOCKS5, proxy_ip, int(proxy_port))
        # Подменяем стандартный сокет на прокси-сокет
        socket.socket = socks.socksocket
        # Выполняем тестовый запрос через SOCKS прокси
        response = requests.get("https://www.google.com", timeout=10)
        # Проверка успешности запроса
        if response.status_code == 200:
            return f"SOCKS запрос выполнен успешно, статус: {response.status_code}"
        else:
            return f"Ошибка запроса через SOCKS прокси, статус: {response.status_code}"

    except requests.RequestException as e:
        return f"Ошибка запроса через SOCKS прокси: {e}"
    except Exception as e:
        return f"Ошибка подключения через SOCKS прокси: {e}"
