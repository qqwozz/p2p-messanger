from flask import Flask, request, jsonify

"""
Простейший сигнальный сервер для p2p-мессенджера.

Идея:
- клиенты регистрируются по HTTP и сообщают своё локальное UDP-порт;
- сервер запоминает (username -> внешний IP + UDP-порт, который сообщил клиент);
- второй клиент может запросить endpoint по username;
- по сути это очень упрощённый STUN-like механизм: клиент узнаёт свой внешний IP
  через request.remote_addr.

Это НЕ безопасный и НЕ масштабируемый сервер, а учебный пример.
"""

app = Flask(__name__)

# username -> {"ip": str, "port": int}
peers = {}


@app.route("/register", methods=["POST"])
def register():
    """
    Регистрация пира.

    Клиент шлёт:
        POST /register
        JSON: {"username": "alice", "port": 50000}

    Сервер запоминает:
        - username
        - внешний IP (request.remote_addr)
        - UDP-порт, который клиент указал (это порт, к которому у него привязан UDP-сокет)

    Ответ:
        {
            "status": "ok",
            "ip": "<detected external ip>",
            "port": <udp_port>
        }
    """
    data = request.get_json(force=True)
    username = data.get("username")
    port = int(data.get("port"))

    if not username:
        return jsonify({"status": "error", "error": "username required"}), 400

    peer_ip = request.remote_addr
    peers[username] = {"ip": peer_ip, "port": port}
    return jsonify({"status": "ok", "ip": peer_ip, "port": port})


@app.route("/lookup/<username>", methods=["GET"])
def lookup(username: str):
    """
    Запрос информации о пире по username.

    Ответ:
        {
            "peer": {"ip": "...", "port": ...}  # если найден
        }
        или
        {
            "peer": null
        }
    """
    return jsonify({"peer": peers.get(username)})


@app.route("/whoami", methods=["GET"])
def whoami():
    """
    Простейший STUN-like endpoint.

    Возвращает внешний IP и TCP-порт HTTP-соединения:
        {
            "ip": "<remote_addr>",
            "port": <remote_port_if_available_or_null>
        }
    """
    # У Flask нет прямого доступа к remote_port, поэтому для простоты
    # возвращаем только IP и port=None.
    return jsonify({"ip": request.remote_addr, "port": None})


if __name__ == "__main__":
    # Запускаем на всех интерфейсах, порт по умолчанию 5000.
    # В продакшене лучше использовать gunicorn/uwsgi и т.п.
    app.run(host="0.0.0.0", port=5000, debug=True)

