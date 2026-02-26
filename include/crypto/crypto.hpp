#pragma once

#include <string>
#include <vector>

// Весь код модуля crypto максимально простой и использует OpenSSL.
// Основная идея:
// - RSA-4096 для асимметричных операций (ключи, подписи, обмен сеансовым ключом)
// - AES-256-GCM для симметричного шифрования сообщений
// - Небольшие функции для простого "handshake" (обмен общего сеансового ключа)

namespace crypto {

// Структура с результатом шифрования AES-GCM
struct AesGcmCiphertext {
    std::vector<unsigned char> iv;          // случайный вектор инициализации (nonce)
    std::vector<unsigned char> tag;         // тег аутентификации GCM
    std::vector<unsigned char> ciphertext;  // зашифрованные данные
};

// Простая обёртка над парой RSA-ключей.
// Внутри используется OpenSSL, но наружу торчит только удобный C++ интерфейс.
class RsaKeyPair {
public:
    // Генерация новой пары ключей RSA (по умолчанию 4096 бит).
    static RsaKeyPair generate(int bits = 4096);

    RsaKeyPair();
    RsaKeyPair(const RsaKeyPair& other);
    RsaKeyPair& operator=(const RsaKeyPair& other);
    RsaKeyPair(RsaKeyPair&& other) noexcept;
    RsaKeyPair& operator=(RsaKeyPair&& other) noexcept;
    ~RsaKeyPair();

    // Сохранение приватного и публичного ключей в PEM-файлы.
    void save_private_pem(const std::string& path) const;
    void save_public_pem(const std::string& path) const;

    // Загрузка ключей из PEM-файлов.
    static RsaKeyPair load_private_pem(const std::string& path);
    static RsaKeyPair load_public_pem(const std::string& path);

    // Экспорт ключей в PEM-строки (удобно для отправки по сети/логов).
    std::string private_pem() const;
    std::string public_pem() const;

    // Подпись произвольных данных (SHA-256 + RSA-PSS).
    std::vector<unsigned char> sign(const std::vector<unsigned char>& data) const;

    // Проверка подписи.
    bool verify(const std::vector<unsigned char>& data,
                const std::vector<unsigned char>& signature) const;

    // Проверка, есть ли приватный ключ (иногда может быть только публичный).
    bool has_private_key() const;

    // Доступ к "сыраям" OpenSSL-ключа не раскрывается наружу,
    // чтобы максимально упростить использование и не привязывать пользователя к OpenSSL API.

private:
    // Внутренний указатель на EVP_PKEY (универсальный контейнер ключей в OpenSSL).
    void* pkey_;  // фактически EVP_PKEY*, но прячем тип в заголовке

    explicit RsaKeyPair(void* pkey);
};

// --- AES-256-GCM ---

// Шифрование при помощи AES-256-GCM.
// - key должен быть ровно 32 байта (256 бит).
// - optional_aad - дополнительные аутентифицируемые данные (не шифруются, но защищаются).
AesGcmCiphertext aes256_gcm_encrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& optional_aad = {});

// Расшифровка AES-256-GCM.
// Бросает std::runtime_error, если проверка тега аутентификации не прошла.
std::vector<unsigned char> aes256_gcm_decrypt(
    const std::vector<unsigned char>& key,
    const AesGcmCiphertext& bundle,
    const std::vector<unsigned char>& optional_aad = {});

// --- Простейший handshake ---
//
// Идея:
// 1) Инициатор генерирует случайный сеансовый ключ AES-256 (32 байта).
// 2) Шифрует этот ключ публичным RSA-ключом получателя.
// 3) Подписывает зашифрованный ключ своим приватным RSA-ключом.
// 4) Отправляет структуру HandshakeMessage.
// 5) Получатель расшифровывает сеансовый ключ своим приватным ключом
//    и проверяет подпись с использованием публичного ключа инициатора.
// В итоге обе стороны получают общий симметричный ключ для AES.

struct HandshakeMessage {
    std::vector<unsigned char> encrypted_session_key;  // RSA-шифртекст сеансового ключа
    std::vector<unsigned char> signature;              // подпись отправителя по encrypted_session_key
};

// Создание handshake-запроса.
// - sender: пара ключей отправителя (нужен приватный для подписи)
// - receiver_public_pem: публичный ключ получателя в PEM-формате
// - out_session_key: сюда будет записан сгенерированный сеансовый ключ AES-256
// Возвращает структуру, которую можно отправить по сети.
HandshakeMessage create_handshake_request(
    const RsaKeyPair& sender,
    const std::string& receiver_public_pem,
    std::vector<unsigned char>& out_session_key);

// Обработка handshake-запроса на стороне получателя.
// - receiver: пара ключей получателя (нужен приватный для расшифровки)
// - sender_public_pem: публичный ключ отправителя в PEM-формате (для проверки подписи)
// - msg: полученное рукопожатие
// Возвращает восстановленный общий сеансовый ключ AES-256.
std::vector<unsigned char> process_handshake_request(
    const RsaKeyPair& receiver,
    const std::string& sender_public_pem,
    const HandshakeMessage& msg);

}  // namespace crypto

