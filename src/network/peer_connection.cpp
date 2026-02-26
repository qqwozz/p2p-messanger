#include "network/peer_connection.hpp"

#include <stdexcept>

namespace network {

// --- Вспомогательные функции для работы с int/size_t в big-endian ---
namespace {

std::uint32_t to_be32(std::uint32_t v) {
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) << 8)  |
           ((v & 0x00FF0000u) >> 8)  |
           ((v & 0xFF000000u) >> 24);
}

std::uint32_t from_be32(std::uint32_t v) {
    return to_be32(v);
}

void write_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    std::uint32_t be = to_be32(v);
    out.push_back(static_cast<std::uint8_t>((be >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((be >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((be >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(be & 0xFF));
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& buf, std::size_t& offset) {
    if (offset + 4 > buf.size()) {
        throw std::runtime_error("buffer too small for u32");
    }
    std::uint32_t v = 0;
    v |= static_cast<std::uint32_t>(buf[offset]) << 24;
    v |= static_cast<std::uint32_t>(buf[offset + 1]) << 16;
    v |= static_cast<std::uint32_t>(buf[offset + 2]) << 8;
    v |= static_cast<std::uint32_t>(buf[offset + 3]);
    offset += 4;
    return from_be32(v);
}

}  // namespace

PeerConnection::PeerConnection(UdpEndpoint& udp,
                               crypto::RsaKeyPair self_keys,
                               std::string peer_id,
                               std::string peer_public_pem,
                               const boost::asio::ip::udp::endpoint& remote_endpoint)
    : udp_(udp),
      self_keys_(std::move(self_keys)),
      peer_id_(std::move(peer_id)),
      peer_public_pem_(std::move(peer_public_pem)),
      remote_(remote_endpoint) {}

bool PeerConnection::connectToPeer(const std::string& peer_id) {
    // В этой простой реализации peer_id в параметре никак не используется:
    // весь контекст (peer_public_pem_ и remote_) мы уже получили извне.
    (void)peer_id;

    if (state_ != State::DISCONNECTED) {
        return false;
    }

    sendHandshake();
    state_ = State::HANDSHAKE_SENT;
    return true;
}

void PeerConnection::handleIncomingPacket(const Packet& pkt,
                                          const boost::asio::ip::udp::endpoint& from) {
    // Минимальная защита: игнорируем пакеты не от ожидаемого endpoint.
    if (from.address() != remote_.address() || from.port() != remote_.port()) {
        return;
    }

    switch (pkt.type) {
        case PacketType::Handshake:
            handleHandshake(pkt);
            break;
        case PacketType::Ack:
            handleAck(pkt);
            break;
        case PacketType::Data:
            handleData(pkt);
            break;
        case PacketType::KeepAlive:
            // На keep-alive можно не отвечать, достаточно просто принимать.
            break;
    }
}

std::string PeerConnection::sendEncryptedMessage(const std::string& plaintext) {
    // Генерируем простой message_id вида "msg-<номер>".
    std::string message_id = "msg-" + std::to_string(next_message_id_++);

    if (!is_established()) {
        // Соединение ещё не готово — просто кладём сообщение в очередь.
        queued_before_establish_.push_back(plaintext);
        return message_id;
    }

    // Шифруем сообщение с помощью уже установленного сеансового AES-ключа.
    std::vector<std::uint8_t> plain_bytes(plaintext.begin(), plaintext.end());
    auto cipher = crypto::aes256_gcm_encrypt(session_key_, plain_bytes);

    // Сериализуем шифртекст в payload Packet::Data.
    std::vector<std::uint8_t> payload = serializeCipher(cipher);

    // Увеличиваем seq для нового пакета.
    std::uint32_t seq = next_seq_++;

    Packet pkt;
    pkt.type = PacketType::Data;
    pkt.seq = seq;
    pkt.payload = payload;

    // Сохраняем в таблицу неподтверждённых сообщений.
    OutgoingMessage msg;
    msg.message_id = message_id;
    msg.encrypted_data = payload;
    msg.last_send_time = std::chrono::steady_clock::now();
    msg.retry_count = 0;
    msg.seq = seq;

    pending_[message_id] = msg;
    seq_to_id_[seq] = message_id;

    // Отправляем пакет по сети.
    sendPacket(pkt);

    return message_id;
}

void PeerConnection::tick(std::chrono::milliseconds retry_interval,
                          int max_retries) {
    if (!is_established()) {
        return;
    }

    const auto now = std::chrono::steady_clock::now();

    std::vector<std::string> to_erase;

    for (auto& kv : pending_) {
        auto& msg = kv.second;

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - msg.last_send_time);
        if (elapsed < retry_interval) {
            continue;
        }

        if (msg.retry_count >= max_retries) {
            // В самой простой версии просто перестаём пытаться.
            to_erase.push_back(kv.first);
            continue;
        }

        // Переотправляем пакет с тем же seq и payload.
        Packet pkt;
        pkt.type = PacketType::Data;
        pkt.seq = msg.seq;
        pkt.payload = msg.encrypted_data;

        sendPacket(pkt);

        msg.retry_count += 1;
        msg.last_send_time = now;
    }

    for (const auto& id : to_erase) {
        pending_.erase(id);
    }
}

void PeerConnection::sendHandshake() {
    // Инициатор генерирует общий сеансовый ключ и шифрует его публичным ключом пира.
    std::vector<std::uint8_t> session;
    auto hs = crypto::create_handshake_request(self_keys_, peer_public_pem_, session);

    session_key_ = std::move(session);

    Packet pkt;
    pkt.type = PacketType::Handshake;
    pkt.seq = next_seq_++;
    pkt.payload = serializeHandshake(hs);

    sendPacket(pkt);
}

void PeerConnection::handleHandshake(const Packet& pkt) {
    // Если мы уже установили сессию, повторные handshake можно игнорировать.
    if (state_ == State::ESTABLISHED) {
        return;
    }

    // Разбираем HandshakeMessage из payload.
    crypto::HandshakeMessage msg = parseHandshakePayload(pkt.payload);

    if (!self_keys_.has_private_key()) {
        throw std::runtime_error("PeerConnection: private key required to process handshake");
    }

    // Восстанавливаем сеансовый AES-ключ.
    auto session = crypto::process_handshake_request(self_keys_, peer_public_pem_, msg);
    session_key_ = std::move(session);

    state_ = State::KEY_EXCHANGE;

    // Простейшее подтверждение: отправляем Ack с тем же seq.
    Packet ack;
    ack.type = PacketType::Ack;
    ack.seq = pkt.seq;
    ack.payload.clear();
    sendPacket(ack);

    state_ = State::ESTABLISHED;

    // После установки сессии пробуем разослать отложенные сообщения.
    flushPendingOnEstablish();
}

void PeerConnection::handleAck(const Packet& pkt) {
    auto it = seq_to_id_.find(pkt.seq);
    if (it != seq_to_id_.end()) {
        const std::string& id = it->second;
        pending_.erase(id);
        seq_to_id_.erase(it);
    }

    // Если мы ещё на этапе отправленного handshake, то первое Ack считаем
    // подтверждением успешного рукопожатия и устанавливаем сессию с нашей стороны.
    if (state_ == State::HANDSHAKE_SENT) {
        state_ = State::ESTABLISHED;
        flushPendingOnEstablish();
    }
}

void PeerConnection::handleData(const Packet& pkt) {
    if (!is_established()) {
        // В простейшем варианте игнорируем данные до установки сессии.
        return;
    }

    std::size_t offset = 0;
    auto cipher = parseCipher(pkt.payload, offset);

    // Пытаемся расшифровать.
    std::vector<std::uint8_t> plain;
    try {
        plain = crypto::aes256_gcm_decrypt(session_key_, cipher);
    } catch (const std::exception&) {
        // Если аутентификация не прошла, просто игнорируем пакет.
        return;
    }

    // В этой учебной реализации мы не передаём расшифрованное сообщение наверх.
    // Здесь мог бы быть callback on_message(const std::string&).
    (void)plain;

    // Отправляем Ack, чтобы отправитель мог убрать сообщение из pending_.
    Packet ack;
    ack.type = PacketType::Ack;
    ack.seq = pkt.seq;
    ack.payload.clear();
    sendPacket(ack);
}

std::vector<std::uint8_t> PeerConnection::serializeHandshake(
    const crypto::HandshakeMessage& msg) const {
    std::vector<std::uint8_t> out;
    // Формат:
    // [4 байта len_enc][len_enc байт encrypted_session_key]
    // [4 байта len_sig][len_sig байт signature]
    write_u32(out, static_cast<std::uint32_t>(msg.encrypted_session_key.size()));
    out.insert(out.end(), msg.encrypted_session_key.begin(), msg.encrypted_session_key.end());

    write_u32(out, static_cast<std::uint32_t>(msg.signature.size()));
    out.insert(out.end(), msg.signature.begin(), msg.signature.end());

    return out;
}

crypto::HandshakeMessage PeerConnection::parseHandshakePayload(
    const std::vector<std::uint8_t>& payload) const {
    std::size_t offset = 0;
    crypto::HandshakeMessage msg;

    std::uint32_t len_enc = read_u32(payload, offset);
    if (offset + len_enc > payload.size()) {
        throw std::runtime_error("handshake payload truncated (enc)");
    }
    msg.encrypted_session_key.assign(payload.begin() + static_cast<long>(offset),
                                     payload.begin() + static_cast<long>(offset + len_enc));
    offset += len_enc;

    std::uint32_t len_sig = read_u32(payload, offset);
    if (offset + len_sig > payload.size()) {
        throw std::runtime_error("handshake payload truncated (sig)");
    }
    msg.signature.assign(payload.begin() + static_cast<long>(offset),
                         payload.begin() + static_cast<long>(offset + len_sig));
    offset += len_sig;

    return msg;
}

std::vector<std::uint8_t> PeerConnection::serializeCipher(
    const crypto::AesGcmCiphertext& c) const {
    std::vector<std::uint8_t> out;
    // Формат:
    // [4 байта len_iv][len_iv байт iv]
    // [4 байта len_tag][len_tag байт tag]
    // [4 байта len_ct][len_ct байт ciphertext]
    write_u32(out, static_cast<std::uint32_t>(c.iv.size()));
    out.insert(out.end(), c.iv.begin(), c.iv.end());

    write_u32(out, static_cast<std::uint32_t>(c.tag.size()));
    out.insert(out.end(), c.tag.begin(), c.tag.end());

    write_u32(out, static_cast<std::uint32_t>(c.ciphertext.size()));
    out.insert(out.end(), c.ciphertext.begin(), c.ciphertext.end());

    return out;
}

crypto::AesGcmCiphertext PeerConnection::parseCipher(
    const std::vector<std::uint8_t>& payload,
    std::size_t& offset) const {
    crypto::AesGcmCiphertext c;

    std::uint32_t len_iv = read_u32(payload, offset);
    if (offset + len_iv > payload.size()) {
        throw std::runtime_error("cipher payload truncated (iv)");
    }
    c.iv.assign(payload.begin() + static_cast<long>(offset),
                payload.begin() + static_cast<long>(offset + len_iv));
    offset += len_iv;

    std::uint32_t len_tag = read_u32(payload, offset);
    if (offset + len_tag > payload.size()) {
        throw std::runtime_error("cipher payload truncated (tag)");
    }
    c.tag.assign(payload.begin() + static_cast<long>(offset),
                 payload.begin() + static_cast<long>(offset + len_tag));
    offset += len_tag;

    std::uint32_t len_ct = read_u32(payload, offset);
    if (offset + len_ct > payload.size()) {
        throw std::runtime_error("cipher payload truncated (ct)");
    }
    c.ciphertext.assign(payload.begin() + static_cast<long>(offset),
                        payload.begin() + static_cast<long>(offset + len_ct));
    offset += len_ct;

    return c;
}

void PeerConnection::sendPacket(const Packet& pkt) {
    auto bytes = serialize_packet(pkt);
    udp_.send_to(bytes, remote_);
}

void PeerConnection::flushPendingOnEstablish() {
    if (!is_established()) {
        return;
    }

    for (const auto& text : queued_before_establish_) {
        sendEncryptedMessage(text);
    }
    queued_before_establish_.clear();
}

}  // namespace network

