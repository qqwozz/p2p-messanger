#include "network/network.hpp"

#include <chrono>
#include <stdexcept>
#include <thread>

namespace network {

// --- Вспомогательные функции для работы с целыми в big-endian ---

namespace {

std::uint32_t to_be32(std::uint32_t v) {
    // Простейшая ручная конверсия в big-endian, чтобы не зависеть от htonl.
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) << 8)  |
           ((v & 0x00FF0000u) >> 8)  |
           ((v & 0xFF000000u) >> 24);
}

std::uint32_t from_be32(std::uint32_t v) {
    // Обратная операция идентична to_be32 (перестановка тех же байтов).
    return to_be32(v);
}

}  // namespace

// --- Сериализация пакетов ---

std::vector<std::uint8_t> serialize_packet(const Packet& p) {
    std::vector<std::uint8_t> out;
    out.reserve(1 + 4 + p.payload.size());

    out.push_back(static_cast<std::uint8_t>(p.type));

    std::uint32_t seq_be = to_be32(p.seq);
    out.push_back(static_cast<std::uint8_t>((seq_be >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((seq_be >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((seq_be >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(seq_be & 0xFF));

    out.insert(out.end(), p.payload.begin(), p.payload.end());

    return out;
}

Packet parse_packet(const std::uint8_t* data, std::size_t size) {
    if (size < 5) {
        throw std::runtime_error("packet too small");
    }

    Packet p;
    p.type = static_cast<PacketType>(data[0]);

    std::uint32_t seq_be = 0;
    seq_be |= (static_cast<std::uint32_t>(data[1]) << 24);
    seq_be |= (static_cast<std::uint32_t>(data[2]) << 16);
    seq_be |= (static_cast<std::uint32_t>(data[3]) << 8);
    seq_be |= (static_cast<std::uint32_t>(data[4]));

    p.seq = from_be32(seq_be);
    p.payload.assign(data + 5, data + size);
    return p;
}

// --- UdpEndpoint ---

UdpEndpoint::UdpEndpoint(boost::asio::io_context& io, std::uint16_t local_port)
    : socket_(io) {
    using boost::asio::ip::udp;

    udp::endpoint bind_endpoint(udp::v4(), local_port);
    socket_.open(udp::v4());
    socket_.bind(bind_endpoint);

    // Делаем сокет неблокирующим, чтобы вручную реализовать ожидание с таймаутом.
    socket_.non_blocking(true);
}

std::uint16_t UdpEndpoint::local_port() const {
    return socket_.local_endpoint().port();
}

void UdpEndpoint::send_to(const std::vector<std::uint8_t>& data,
                          const boost::asio::ip::udp::endpoint& remote) {
    boost::system::error_code ec;
    auto bytes = socket_.send_to(boost::asio::buffer(data), remote, 0, ec);
    (void)bytes;
    if (ec) {
        throw std::runtime_error("send_to failed: " + ec.message());
    }
}

bool UdpEndpoint::receive_from(std::vector<std::uint8_t>& buffer,
                               boost::asio::ip::udp::endpoint& remote,
                               std::chrono::milliseconds timeout) {
    using clock = std::chrono::steady_clock;
    auto deadline = clock::now() + timeout;

    buffer.resize(2048);  // достаточно для небольших служебных/тестовых пакетов

    while (clock::now() < deadline) {
        boost::system::error_code ec;
        std::size_t len = socket_.receive_from(boost::asio::buffer(buffer), remote, 0, ec);

        if (!ec) {
            buffer.resize(len);
            return true;  // что-то получили
        }

        if (ec == boost::asio::error::would_block ||
            ec == boost::asio::error::try_again) {
            // Данных пока нет — немного подождём и попробуем ещё.
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        // Любая другая ошибка — считаем фатальной.
        throw std::runtime_error("receive_from failed: " + ec.message());
    }

    // Вышли по таймауту.
    buffer.clear();
    return false;
}

// --- UDP hole punching ---

bool udp_hole_punch(UdpEndpoint& endpoint,
                    const boost::asio::ip::udp::endpoint& remote,
                    std::chrono::milliseconds per_try_timeout,
                    int max_retries) {
    // seq можно использовать как простой счётчик попыток.
    std::uint32_t seq = 1;

    for (int attempt = 0; attempt < max_retries; ++attempt, ++seq) {
        // 1. Отправляем Handshake-пакет на внешний endpoint собеседника.
        Packet out;
        out.type = PacketType::Handshake;
        out.seq = seq;
        out.payload.clear();  // нам не нужны данные, важен сам факт трафика

        auto bytes = serialize_packet(out);
        endpoint.send_to(bytes, remote);

        // 2. Ждём ответ в течение per_try_timeout.
        std::vector<std::uint8_t> buf;
        boost::asio::ip::udp::endpoint sender;
        bool got = endpoint.receive_from(buf, sender, per_try_timeout);

        if (!got) {
            // Таймаут — просто пробуем ещё раз.
            continue;
        }

        try {
            Packet in = parse_packet(buf.data(), buf.size());

            // Если пришёл Handshake/Data/KeepAlive от ожидаемого endpoint —
            // считаем, что "дырка" пробита.
            if (sender.address() == remote.address() &&
                sender.port() == remote.port() &&
                (in.type == PacketType::Handshake ||
                 in.type == PacketType::Data ||
                 in.type == PacketType::KeepAlive)) {
                return true;
            }
        } catch (...) {
            // Неверный пакет просто игнорируем и продолжаем попытки.
        }
    }

    // После max_retries так и не удалось получить ответ — считаем неуспехом.
    return false;
}

// --- Keep-alive ---

void keep_alive_loop(UdpEndpoint& endpoint,
                     const boost::asio::ip::udp::endpoint& remote,
                     std::chrono::seconds interval,
                     std::atomic_bool& stop_flag) {
    std::uint32_t seq = 1;

    while (!stop_flag.load()) {
        Packet p;
        p.type = PacketType::KeepAlive;
        p.seq = seq++;
        p.payload.clear();

        auto bytes = serialize_packet(p);
        try {
            endpoint.send_to(bytes, remote);
        } catch (...) {
            // Для простоты keep-alive просто игнорирует ошибки отправки.
        }

        std::this_thread::sleep_for(interval);
    }
}

}  // namespace network

