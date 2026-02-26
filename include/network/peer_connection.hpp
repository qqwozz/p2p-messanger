#pragma once

// PeerConnection — высокоуровневое соединение с одним пировым участником.
//
// Цели:
// - инкапсулировать протокол handshake и установку общей AES-сессии;
// - управлять состоянием соединения (state-machine);
// - отправлять/принимать зашифрованные сообщения поверх UDP-пакетов network::Packet;
// - держать очередь неподтверждённых сообщений и переотправлять их.
//
// Эта реализация максимально простая и синхронная:
// - класс не владеет собственным потоком приёма;
// - приложение снаружи читает UDP-пакеты и передаёт их в handleIncomingPacket();
// - таймеры/ретрансмиссии реализуются через периодический вызов tick().

#include "crypto/crypto.hpp"
#include "network/network.hpp"

#include <chrono>
#include <string>
#include <unordered_map>
#include <vector>

namespace network {

// Исходящее сообщение, ожидающее подтверждения.
struct OutgoingMessage {
    std::string message_id;  // логический идентификатор сообщения
    std::vector<std::uint8_t> encrypted_data;  // то, что отправляем в payload (AES-шифртекст)
    std::chrono::steady_clock::time_point last_send_time;  // когда последний раз отправляли
    int retry_count;  // сколько раз уже пытались отправить
    std::uint32_t seq;  // seq из Packet, по нему приходят Ack
};

class PeerConnection {
public:
    enum class State {
        DISCONNECTED,
        HANDSHAKE_SENT,
        HANDSHAKE_RECEIVED,
        KEY_EXCHANGE,
        ESTABLISHED
    };

    // Конструктор получает:
    // - ссылку на уже существующий UdpEndpoint (по нему шлём все пакеты),
    // - нашу пару RSA-ключей,
    // - идентификатор пира (логическое имя, как на сигнальном сервере),
    // - публичный ключ пира в PEM-формате,
    // - внешний UDP-endpoint пира (ip:port), полученный через сигнальный сервер.
    PeerConnection(UdpEndpoint& udp,
                   crypto::RsaKeyPair self_keys,
                   std::string peer_id,
                   std::string peer_public_pem,
                   const boost::asio::ip::udp::endpoint& remote_endpoint);

    State state() const { return state_; }
    bool is_established() const { return state_ == State::ESTABLISHED; }

    // Количество сообщений, ожидающих подтверждения (для отладки/тестов).
    std::size_t pendingCount() const { return pending_.size(); }

    const std::string& peer_id() const { return peer_id_; }

    // Инициировать соединение с пиром.
    // В самом простом варианте:
    // - сразу шлём handshake-пакет (createHandshake());
    // - переходим в состояние HANDSHAKE_SENT;
    // - дальше ждём Ack и/или handshake от пира через handleIncomingPacket().
    bool connectToPeer(const std::string& peer_id);

    // Высокоуровневая обработка входящих пакетов от этого пира.
    // Вызывается приложением, когда оно прочитало UDP-пакет и разобрало его в Packet.
    void handleIncomingPacket(const Packet& pkt,
                              const boost::asio::ip::udp::endpoint& from);

    // Отправка зашифрованного сообщения.
    // - если сессия ещё не ESTABLISHED, сообщение попадает в очередь и будет
    //   отправлено после успешного рукопожатия;
    // - возвращает message_id, по которому можно отслеживать доставку.
    std::string sendEncryptedMessage(const std::string& plaintext);

    // Периодический "тик" для ретрансмиссий.
    // Приложение может вызывать его, например, раз в 100–200 мс.
    void tick(std::chrono::milliseconds retry_interval,
              int max_retries);

private:
    // Внутренние помощники.
    void sendHandshake();                // формирование и отправка handshake-пакета
    void handleHandshake(const Packet&); // разбор входящего handshake-пакета
    void handleAck(const Packet&);       // обработка подтверждения доставки
    void handleData(const Packet&);      // обработка входящего зашифрованного сообщения

    // Сериализация/десериализация crypto::HandshakeMessage в payload Packet.
    std::vector<std::uint8_t> serializeHandshake(const crypto::HandshakeMessage& msg) const;
    crypto::HandshakeMessage parseHandshakePayload(const std::vector<std::uint8_t>& payload) const;

    // Сериализация AES-шифртекста для передачи внутри Packet::payload.
    std::vector<std::uint8_t> serializeCipher(const crypto::AesGcmCiphertext& c) const;
    crypto::AesGcmCiphertext parseCipher(const std::vector<std::uint8_t>& payload,
                                         std::size_t& offset) const;

    // Вспомогательная отправка Packet на remote_endpoint_.
    void sendPacket(const Packet& pkt);

    // Рассылаем все отложенные (ждущие ESTABLISHED) сообщения.
    void flushPendingOnEstablish();

private:
    UdpEndpoint& udp_;
    crypto::RsaKeyPair self_keys_;
    std::string peer_id_;
    std::string peer_public_pem_;
    boost::asio::ip::udp::endpoint remote_;

    State state_{State::DISCONNECTED};

    // Общий сеансовый ключ AES-256, устанавливается после успешного handshake.
    std::vector<std::uint8_t> session_key_;  // 32 байта

    // Очередь сообщений, которые хотели отправить, но соединение ещё не ESTABLISHED.
    std::vector<std::string> queued_before_establish_;

    // Неподтверждённые исходящие сообщения (по message_id).
    std::unordered_map<std::string, OutgoingMessage> pending_;

    // Быстрый поиск message_id по seq (для Ack).
    std::unordered_map<std::uint32_t, std::string> seq_to_id_;

    // Локальный счётчик seq для исходящих пакетов.
    std::uint32_t next_seq_{1};

    // Простейший счётчик для генерации message_id.
    std::uint64_t next_message_id_{1};
};

}  // namespace network

