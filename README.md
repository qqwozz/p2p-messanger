# p2p-messanger

Простой демонстрационный p2p-мессенджер (пока только криптографическое ядро), написанный на C++ с использованием OpenSSL.

### Возможности модуля `crypto`

- Генерация RSA-ключей (по умолчанию 4096 бит)
- Сохранение/загрузка ключей в PEM-формате (файлы и строки)
- Подпись и проверка подписей (SHA-256 + RSA-PSS)
- Симметричное шифрование AES-256-GCM (аутентифицированное шифрование)
- Простейший handshake для обмена сеансовым AES-ключом между двумя участниками
- Тесты на корректность шифрования/подписи и на базовую производительность

### Зависимости

- CMake 3.16+
- Компилятор с поддержкой C++17
- OpenSSL (библиотека `libcrypto`)
- Boost.Asio (через пакет `libboost-system`)
- ncurses (для консольного интерфейса)

На Ubuntu/Debian можно установить так:

```bash
sudo apt install build-essential cmake libssl-dev libboost-system-dev libncurses-dev
```

### Сборка и запуск тестов

```bash
cmake -S . -B build
cmake --build build -j4
cd build
ctest --output-on-failure
```

Будут собраны библиотеки, тесты и пример клиента:

- `crypto` + `crypto_tests`
- `network` + `network_tests`
- `console_client` — простейший консольный чат-клиент на ncurses

`crypto_tests`:

- генерирует две пары RSA-ключей (Alice и Bob),
- проверяет сохранение/загрузку PEM,
- шифрует/расшифровывает строку с помощью AES-256-GCM,
- подписывает и проверяет подпись сообщения,
- выполняет handshake между Alice и Bob и сравнивает сеансовые ключи,
- замеряет время выполнения нескольких тысяч операций шифрования и подписи.

`network_tests`:

- проверяет сериализацию/десериализацию пакетов,
- отправляет UDP-пакет от одного локального endpoint'а к другому,
- локально симулирует UDP hole punching (оба участника на `127.0.0.1`),
- проверяет, что keep-alive цикл запускается и корректно останавливается.

### Как использовать библиотеку

```cpp
#include "crypto/crypto.hpp"
using namespace crypto;

// Генерация ключей RSA-4096
RsaKeyPair alice = RsaKeyPair::generate(4096);
RsaKeyPair bob   = RsaKeyPair::generate(4096);

// Сохранение/загрузка PEM
alice.save_private_pem("alice_private.pem");
alice.save_public_pem("alice_public.pem");
auto alice_priv = RsaKeyPair::load_private_pem("alice_private.pem");
auto alice_pub  = RsaKeyPair::load_public_pem("alice_public.pem");

// Подпись и проверка
std::string msg = "hello";
auto sig = alice_priv.sign(std::vector<unsigned char>(msg.begin(), msg.end()));
bool ok  = alice_pub.verify(std::vector<unsigned char>(msg.begin(), msg.end()), sig);

// AES-256-GCM
std::vector<unsigned char> key(32, 0x11); // 32-байтовый ключ
std::string plaintext = "secret";
auto cipher = aes256_gcm_encrypt(key,
    std::vector<unsigned char>(plaintext.begin(), plaintext.end()));
auto decrypted = aes256_gcm_decrypt(key, cipher);

// Handshake (Alice -> Bob)
std::vector<unsigned char> alice_session_key;
auto handshake_msg = create_handshake_request(
    alice,               // отправитель (с приватным ключом)
    bob.public_pem(),    // публичный ключ Bob
    alice_session_key    // сюда запишется сеансовый ключ AES-256
);

auto bob_session_key = process_handshake_request(
    bob,                 // получатель (с приватным ключом)
    alice.public_pem(),  // публичный ключ Alice
    handshake_msg
);

// alice_session_key и bob_session_key должны совпасть и могут использоваться
// как общий симметричный ключ для шифрования сообщений по AES-256-GCM.
```

### Замечания по безопасности

Код сделан максимально простым для демонстрации:

- приватные ключи сохраняются в PEM **без шифрования**, в реальном приложении их нужно защищать (пароль, HSM и т.п.);
- handshake не учитывает версии протокола, идентификаторы участников и защиту от повторной отправки сообщений;
- не реализована проверка сертификатов/PKI — публичные ключи подразумеваются доверенными.

Для реального продакшена эти моменты нужно доработать, но как учебный пример и база для p2p-мессенджера модуль подходит.

---

### Сетевой модуль `network` (UDP + NAT traversal)

Файлы:

- `include/network/network.hpp`
- `src/network/network.cpp`
- `tests/network_tests.cpp`

Основные сущности:

- **`network::Packet`**: простой бинарный формат
  - 1 байт: `PacketType` (`Handshake`, `Data`, `KeepAlive`, `Ack`)
  - 4 байта: `seq` (счётчик/идентификатор пакета, big-endian)
  - N байт: полезная нагрузка
- **`serialize_packet` / `parse_packet`**: переводят структуру в/из массива байт.
- **`network::UdpEndpoint`**:
  - обёртка над `boost::asio::ip::udp::socket`,
  - конструктор принимает `io_context` и локальный порт (0 = любой свободный),
  - `send_to(data, endpoint)` — отправка,
  - `receive_from(buffer, remote, timeout)` — блокирующее чтение с таймаутом (через неблокирующий сокет и простой polling).
- **`udp_hole_punch`**:
  - обе стороны знают внешний `ip:port` друг друга (через сигнальный сервер),
  - в цикле отправляют `Handshake` и ждут ответ с таймаутом,
  - если получили подходящий пакет от ожидаемого endpoint — считаем, что отверстие через NAT пробито.
- **`keep_alive_loop`**:
  - в отдельном потоке периодически шлёт `KeepAlive` пакет,
  - останавливается, когда `stop_flag` становится `true`.

Пример использования (локальный обмен):

```cpp
#include "network/network.hpp"
#include <boost/asio.hpp>

boost::asio::io_context io;
network::UdpEndpoint a(io, 0);
network::UdpEndpoint b(io, 0);

auto ep_b = boost::asio::ip::udp::endpoint(
    boost::asio::ip::address::from_string("127.0.0.1"), b.local_port());

network::Packet p;
p.type = network::PacketType::Data;
p.seq = 1;
std::string msg = "hello";
p.payload.assign(msg.begin(), msg.end());

auto raw = network::serialize_packet(p);
a.send_to(raw, ep_b);
```

---

### Сигнальный сервер (STUN-like определение внешнего IP)

Файл: `third_party/signaling_server.py`

- минимальный сервер на Flask;
- хранит `username -> {ip, port}` для зарегистрированных пиров;
- по `request.remote_addr` определяет внешний IP клиента;
- позволяет:
  - зарегистрировать пира с его локальным UDP-портом,
  - спросить endpoint другого пира по username,
  - запросить свой внешний IP (`/whoami`).

Запуск сервера:

```bash
cd third_party
python3 signaling_server.py
```

Маршруты:

- **`POST /register`**

  Тело:

  ```json
  {"username": "alice", "port": 50000}
  ```

  Ответ:

  ```json
  {"status": "ok", "ip": "203.0.113.10", "port": 50000}
  ```

  Где `ip` — внешний IP, который видит сервер (аналог STUN-ответа).

- **`GET /lookup/<username>`**

  Ответ:

  ```json
  {"peer": {"ip": "203.0.113.11", "port": 50001}}
  ```

  или `{"peer": null}`, если такой пользователь ещё не зарегистрирован.

- **`GET /whoami`**

  Возвращает:

  ```json
  {"ip": "203.0.113.10", "port": null}
  ```

  Можно использовать для простейшего "какой у меня внешний IP?".

---

### Этап 3: NAT traversal и тестирование

- **UDP hole punching**:
  - оба клиента A и B:
    1. поднимают локальный UDP-сокет и регистрируются на сигнальном сервере (`/register`);
    2. по username узнают внешний `ip:port` собеседника (`/lookup`);
    3. одновременно вызывают `udp_hole_punch` с endpoint'ом собеседника;
    4. после успеха используют `UdpEndpoint` для обмена реальными сообщениями (`PacketType::Data`).
- **Таймауты и ретрансмиссия**:
  - реализованы внутри `udp_hole_punch` (несколько попыток, ожидание ответа с таймаутом),
  - при желании тот же подход можно применить к надёжной доставке `Data` (посылка `Ack`, повтор при отсутствии `Ack`).
- **Keep-alive**:
  - `keep_alive_loop` периодически шлёт маленькие UDP-пакеты,
  - это помогает NAT не закрывать пробитое отверстие при отсутствии трафика.
- **Тесты**:
  - для реальной проверки NAT traversal — запустить сервер в интернете/VPS и два клиента в разных сетях;
  - для локальной разработки используется `network_tests` (оба пира на `127.0.0.1`), чтобы убедиться, что:
    - формат пакетов корректен,
    - отправка/приём и hole punching логика работают хотя бы без NAT. 

---

### Этап 7: Консольный интерфейс (ncurses)

Файл: `src/ui/console_client.cpp`

Это минимальный TUI-клиент, который демонстрирует:

- список контактов (пока один захардкоженный `peer`) слева;
- окно чата справа;
- строку ввода внизу;
- базовые команды:
  - `/help` — показать доступные команды;
  - `/quit` — выйти.

Сейчас он работает в "офлайн"-режиме:

- набранные сообщения сразу отображаются как `me: ...`;
- затем выводится псевдо-ответ `peer: (echo) ...`;
- сетевой стек (`network` + `PeerConnection`) подключён в виде заголовков, но для простоты не используется.

Запуск консольного клиента:

```bash
cmake -S . -B build
cmake --build build -j4
./build/console_client
```

В дальнейшем сюда можно будет "подвесить" реальные вызовы:

- `PeerConnection::connectToPeer()` при выборе контакта;
- `PeerConnection::sendEncryptedMessage()` при отправке сообщения;
- обработку входящих `Packet` из `UdpEndpoint` в отдельном потоке с добавлением строк в историю чата.
