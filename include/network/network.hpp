#pragma once

// Простейший сетевой слой поверх boost::asio для работы по UDP.
// Идея:
// - обёртка над UDP-сокетом (отправка/получение с таймаутом),
// - очень простой бинарный формат пакетов,
// - минимальный алгоритм UDP hole punching,
// - keep-alive пакеты, чтобы NAT не закрывал "дыру".
//
// Всё сделано максимально просто и синхронно, чтобы было легко читать и отлаживать.

#include <boost/asio.hpp>

#include <atomic>
#include <cstdint>
#include <vector>

namespace network {

// Типы пакетов, которыми будут обмениваться пиры.
enum class PacketType : std::uint8_t {
    Handshake = 1,  // начальные пакеты для hole punching
    Data      = 2,  // пользовательские данные
    KeepAlive = 3,  // периодические keep-alive, чтобы NAT не закрывал порт
    Ack       = 4   // подтверждение доставки (для простейшей ретрансмиссии)
};

// Внутренний формат одного пакета:
// [1 байт type][4 байта seq в big-endian][N байт payload]
struct Packet {
    PacketType type;
    std::uint32_t seq;
    std::vector<std::uint8_t> payload;
};

// Сериализация пакета в непрерывный буфер байт.
std::vector<std::uint8_t> serialize_packet(const Packet& p);

// Обратная операция: разобрать пакет из сырого буфера.
// Бросает std::runtime_error при некорректном формате.
Packet parse_packet(const std::uint8_t* data, std::size_t size);

// Обёртка над UDP-сокетом.
// Содержит только базовые операции: отправка и блокирующее получение с таймаутом.
class UdpEndpoint {
public:
    // io_context живёт снаружи (можно один на всё приложение).
    // local_port = 0 означает "дать любой свободный порт".
    UdpEndpoint(boost::asio::io_context& io, std::uint16_t local_port);

    // Текущий локальный порт, к которому привязан сокет (полезно при local_port = 0).
    std::uint16_t local_port() const;

    // Отправка произвольного массива байт на указанный удалённый endpoint.
    void send_to(const std::vector<std::uint8_t>& data,
                 const boost::asio::ip::udp::endpoint& remote);

    // Блокирующее получение одного датаграммы с таймаутом.
    // - buffer будет перезаписан принятыми байтами.
    // - remote заполнится адресом отправителя.
    // Возвращает true, если что-то получили, и false, если сработал таймаут.
    bool receive_from(std::vector<std::uint8_t>& buffer,
                      boost::asio::ip::udp::endpoint& remote,
                      std::chrono::milliseconds timeout);

    // Доступ к внутреннему сокету, если нужно что-то более низкоуровневое.
    boost::asio::ip::udp::socket& socket() { return socket_; }

private:
    boost::asio::ip::udp::socket socket_;
};

// --- UDP hole punching ---
//
// Идея:
// - у нас уже есть внешний (public) endpoint удалённого пира (ip:port),
//   полученный через сигнальный сервер;
// - обе стороны **одновременно** начинают слать Handshake-пакеты друг другу;
// - NAT по исходящему трафику открывает "дыру" (mapping),
//   и через несколько попыток пиры начинают получать пакеты;
// - как только мы получили от удалённого пира Handshake/Any пакет — считаем,
//   что канал пробит и возвращаем true.
//
// Реализация здесь однопоточная и синхронная:
// - на каждой итерации отправляем Handshake,
// - затем ждём ответ с таймаутом,
// - если за max_retries ничего не пришло — возвращаем false.

bool udp_hole_punch(UdpEndpoint& endpoint,
                    const boost::asio::ip::udp::endpoint& remote,
                    std::chrono::milliseconds per_try_timeout,
                    int max_retries);

// --- Keep-alive ---
//
// Самый простой keep-alive:
// - в отдельном потоке вызываем эту функцию;
// - она шлёт маленький KeepAlive-пакет каждые interval секунд,
//   пока stop_flag не станет true.

void keep_alive_loop(UdpEndpoint& endpoint,
                     const boost::asio::ip::udp::endpoint& remote,
                     std::chrono::seconds interval,
                     std::atomic_bool& stop_flag);

}  // namespace network

