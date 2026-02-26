#include "crypto/crypto.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <cstring>
#include <memory>
#include <stdexcept>

namespace {

// Небольшой помощник для RAII-освобождения OpenSSL-объектов через unique_ptr.
// Deleter может быть любой вызываемый сущностью (функция, лямбда и т.п.).
template <typename T, typename Deleter>
using openssl_ptr = std::unique_ptr<T, Deleter>;

// Обёртка для генерации исключений с понятным текстом.
[[noreturn]] void throw_openssl_error(const char* msg) {
    throw std::runtime_error(msg);
}

// Чтение всего содержимого BIO в std::string.
std::string bio_to_string(BIO* bio) {
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    if (len <= 0 || !data) {
        throw std::runtime_error("BIO_get_mem_data failed");
    }
    return std::string(data, static_cast<size_t>(len));
}

}  // namespace

namespace crypto {

// --- RsaKeyPair реализация ---

RsaKeyPair::RsaKeyPair()
    : pkey_(nullptr) {}

RsaKeyPair::RsaKeyPair(void* pkey)
    : pkey_(pkey) {}

RsaKeyPair::~RsaKeyPair() {
    if (pkey_) {
        EVP_PKEY_free(reinterpret_cast<EVP_PKEY*>(pkey_));
    }
}

RsaKeyPair::RsaKeyPair(const RsaKeyPair& other) : pkey_(nullptr) {
    if (other.pkey_) {
        // У EVP_PKEY есть встроенный счётчик ссылок, используем его.
        EVP_PKEY_up_ref(reinterpret_cast<EVP_PKEY*>(other.pkey_));
        pkey_ = other.pkey_;
    }
}

RsaKeyPair& RsaKeyPair::operator=(const RsaKeyPair& other) {
    if (this == &other) return *this;
    if (pkey_) {
        EVP_PKEY_free(reinterpret_cast<EVP_PKEY*>(pkey_));
        pkey_ = nullptr;
    }
    if (other.pkey_) {
        EVP_PKEY_up_ref(reinterpret_cast<EVP_PKEY*>(other.pkey_));
        pkey_ = other.pkey_;
    }
    return *this;
}

RsaKeyPair::RsaKeyPair(RsaKeyPair&& other) noexcept : pkey_(other.pkey_) {
    other.pkey_ = nullptr;
}

RsaKeyPair& RsaKeyPair::operator=(RsaKeyPair&& other) noexcept {
    if (this == &other) return *this;
    if (pkey_) {
        EVP_PKEY_free(reinterpret_cast<EVP_PKEY*>(pkey_));
    }
    pkey_ = other.pkey_;
    other.pkey_ = nullptr;
    return *this;
}

RsaKeyPair RsaKeyPair::generate(int bits) {
    // Используем высокоуровневый EVP API для генерации RSA-ключа.
    openssl_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) {
        throw_openssl_error("EVP_PKEY_CTX_new_id failed");
    }
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        throw_openssl_error("EVP_PKEY_keygen_init failed");
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0) {
        throw_openssl_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
    }

    EVP_PKEY* raw_pkey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw_pkey) <= 0) {
        throw_openssl_error("EVP_PKEY_keygen failed");
    }

    return RsaKeyPair(raw_pkey);
}

bool RsaKeyPair::has_private_key() const {
    if (!pkey_) return false;
    EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(pkey_);
    // Простая эвристика: если можно выписать приватный ключ в PEM, значит он есть.
    openssl_ptr<BIO, decltype(&BIO_free)> mem(BIO_new(BIO_s_mem()), BIO_free);
    if (!mem) return false;
    if (PEM_write_bio_PrivateKey(mem.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1) {
        return true;
    }
    return false;
}

void RsaKeyPair::save_private_pem(const std::string& path) const {
    if (!pkey_) {
        throw std::runtime_error("No key loaded");
    }
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) {
        throw std::runtime_error("Failed to open private key file for writing");
    }
    EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(pkey_);
    // Пароль/шифрование не используем для простоты, но в реальном приложении
    // приватный ключ должен быть защищён (например, паролем).
    if (PEM_write_PrivateKey(f, key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        fclose(f);
        throw_openssl_error("PEM_write_PrivateKey failed");
    }
    fclose(f);
}

void RsaKeyPair::save_public_pem(const std::string& path) const {
    if (!pkey_) {
        throw std::runtime_error("No key loaded");
    }
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) {
        throw std::runtime_error("Failed to open public key file for writing");
    }
    EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(pkey_);
    if (PEM_write_PUBKEY(f, key) != 1) {
        fclose(f);
        throw_openssl_error("PEM_write_PUBKEY failed");
    }
    fclose(f);
}

RsaKeyPair RsaKeyPair::load_private_pem(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) {
        throw std::runtime_error("Failed to open private key file for reading");
    }
    EVP_PKEY* key = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!key) {
        throw_openssl_error("PEM_read_PrivateKey failed");
    }
    return RsaKeyPair(key);
}

RsaKeyPair RsaKeyPair::load_public_pem(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) {
        throw std::runtime_error("Failed to open public key file for reading");
    }
    EVP_PKEY* key = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!key) {
        throw_openssl_error("PEM_read_PUBKEY failed");
    }
    return RsaKeyPair(key);
}

std::string RsaKeyPair::private_pem() const {
    if (!pkey_) {
        throw std::runtime_error("No key loaded");
    }
    EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(pkey_);
    openssl_ptr<BIO, decltype(&BIO_free)> mem(BIO_new(BIO_s_mem()), BIO_free);
    if (!mem) {
        throw_openssl_error("BIO_new failed");
    }
    if (PEM_write_bio_PrivateKey(mem.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        throw_openssl_error("PEM_write_bio_PrivateKey failed");
    }
    return bio_to_string(mem.get());
}

std::string RsaKeyPair::public_pem() const {
    if (!pkey_) {
        throw std::runtime_error("No key loaded");
    }
    EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(pkey_);
    openssl_ptr<BIO, decltype(&BIO_free)> mem(BIO_new(BIO_s_mem()), BIO_free);
    if (!mem) {
        throw_openssl_error("BIO_new failed");
    }
    if (PEM_write_bio_PUBKEY(mem.get(), key) != 1) {
        throw_openssl_error("PEM_write_bio_PUBKEY failed");
    }
    return bio_to_string(mem.get());
}

std::vector<unsigned char> RsaKeyPair::sign(const std::vector<unsigned char>& data) const {
    if (!pkey_) {
        throw std::runtime_error("No key loaded");
    }

    EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(pkey_);

    openssl_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!mdctx) {
        throw_openssl_error("EVP_MD_CTX_new failed");
    }

    // Используем SHA-256 и RSA-PSS (современный безопасный вариант подписи).
    if (EVP_DigestSignInit(mdctx.get(), nullptr, EVP_sha256(), nullptr, key) != 1) {
        throw_openssl_error("EVP_DigestSignInit failed");
    }

    if (EVP_DigestSignUpdate(mdctx.get(), data.data(), data.size()) != 1) {
        throw_openssl_error("EVP_DigestSignUpdate failed");
    }

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(mdctx.get(), nullptr, &sig_len) != 1) {
        throw_openssl_error("EVP_DigestSignFinal (size) failed");
    }

    std::vector<unsigned char> sig(sig_len);
    if (EVP_DigestSignFinal(mdctx.get(), sig.data(), &sig_len) != 1) {
        throw_openssl_error("EVP_DigestSignFinal failed");
    }
    sig.resize(sig_len);
    return sig;
}

bool RsaKeyPair::verify(const std::vector<unsigned char>& data,
                        const std::vector<unsigned char>& signature) const {
    if (!pkey_) {
        return false;
    }
    EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(pkey_);

    openssl_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!mdctx) {
        return false;
    }

    if (EVP_DigestVerifyInit(mdctx.get(), nullptr, EVP_sha256(), nullptr, key) != 1) {
        return false;
    }

    if (EVP_DigestVerifyUpdate(mdctx.get(), data.data(), data.size()) != 1) {
        return false;
    }

    int ok = EVP_DigestVerifyFinal(mdctx.get(), signature.data(), signature.size());
    return ok == 1;
}

// --- AES-256-GCM реализация ---

AesGcmCiphertext aes256_gcm_encrypt(const std::vector<unsigned char>& key,
                                    const std::vector<unsigned char>& plaintext,
                                    const std::vector<unsigned char>& optional_aad) {
    if (key.size() != 32) {
        throw std::runtime_error("AES-256-GCM key must be 32 bytes");
    }

    // Для простоты используем 12-байтовый IV (рекомендуемый размер для GCM).
    AesGcmCiphertext result;
    result.iv.resize(12);
    if (RAND_bytes(result.iv.data(), static_cast<int>(result.iv.size())) != 1) {
        throw_openssl_error("RAND_bytes failed");
    }

    openssl_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw_openssl_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw_openssl_error("EVP_EncryptInit_ex (cipher) failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                             static_cast<int>(result.iv.size()), nullptr) != 1) {
        throw_openssl_error("EVP_CTRL_GCM_SET_IVLEN failed");
    }

    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), result.iv.data()) != 1) {
        throw_openssl_error("EVP_EncryptInit_ex (key/iv) failed");
    }

    int len = 0;

    // Добавляем AAD, если оно есть.
    if (!optional_aad.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, optional_aad.data(),
                              static_cast<int>(optional_aad.size())) != 1) {
            throw_openssl_error("EVP_EncryptUpdate (AAD) failed");
        }
    }

    result.ciphertext.resize(plaintext.size());

    if (EVP_EncryptUpdate(ctx.get(), result.ciphertext.data(), &len, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1) {
        throw_openssl_error("EVP_EncryptUpdate (data) failed");
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx.get(), result.ciphertext.data() + len, &len) != 1) {
        throw_openssl_error("EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;
    result.ciphertext.resize(ciphertext_len);

    result.tag.resize(16);  // стандартный размер тега GCM
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                             static_cast<int>(result.tag.size()), result.tag.data()) != 1) {
        throw_openssl_error("EVP_CTRL_GCM_GET_TAG failed");
    }

    return result;
}

std::vector<unsigned char> aes256_gcm_decrypt(const std::vector<unsigned char>& key,
                                              const AesGcmCiphertext& bundle,
                                              const std::vector<unsigned char>& optional_aad) {
    if (key.size() != 32) {
        throw std::runtime_error("AES-256-GCM key must be 32 bytes");
    }

    openssl_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw_openssl_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw_openssl_error("EVP_DecryptInit_ex (cipher) failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                             static_cast<int>(bundle.iv.size()), nullptr) != 1) {
        throw_openssl_error("EVP_CTRL_GCM_SET_IVLEN failed");
    }

    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), bundle.iv.data()) != 1) {
        throw_openssl_error("EVP_DecryptInit_ex (key/iv) failed");
    }

    int len = 0;

    if (!optional_aad.empty()) {
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &len, optional_aad.data(),
                              static_cast<int>(optional_aad.size())) != 1) {
            throw_openssl_error("EVP_DecryptUpdate (AAD) failed");
        }
    }

    std::vector<unsigned char> plaintext(bundle.ciphertext.size());

    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, bundle.ciphertext.data(),
                          static_cast<int>(bundle.ciphertext.size())) != 1) {
        throw_openssl_error("EVP_DecryptUpdate (data) failed");
    }
    int plaintext_len = len;

    // Перед финалом нужно установить ожидаемый тег.
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                             static_cast<int>(bundle.tag.size()),
                             const_cast<unsigned char*>(bundle.tag.data())) != 1) {
        throw_openssl_error("EVP_CTRL_GCM_SET_TAG failed");
    }

    int ret = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len);
    if (ret <= 0) {
        // Если тег не совпал, то данные либо повреждены, либо подделаны.
        throw std::runtime_error("AES-GCM authentication failed");
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);
    return plaintext;
}

// --- Handshake реализация ---

HandshakeMessage create_handshake_request(const RsaKeyPair& sender,
                                          const std::string& receiver_public_pem,
                                          std::vector<unsigned char>& out_session_key) {
    if (!sender.has_private_key()) {
        throw std::runtime_error("Sender must have private key for handshake");
    }

    // 1. Генерируем случайный 32-байтовый сеансовый ключ для AES-256.
    out_session_key.resize(32);
    if (RAND_bytes(out_session_key.data(), static_cast<int>(out_session_key.size())) != 1) {
        throw_openssl_error("RAND_bytes failed");
    }

    // 2. Загружаем публичный ключ получателя из PEM-строки.
    openssl_ptr<BIO, decltype(&BIO_free)> mem(
        BIO_new_mem_buf(receiver_public_pem.data(),
                        static_cast<int>(receiver_public_pem.size())),
        BIO_free);
    if (!mem) {
        throw_openssl_error("BIO_new_mem_buf failed");
    }

    openssl_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> receiver_key(
        PEM_read_bio_PUBKEY(mem.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (!receiver_key) {
        throw_openssl_error("PEM_read_bio_PUBKEY failed");
    }

    // 3. Шифруем сеансовый ключ публичным ключом получателя (RSA-OAEP по умолчанию через EVP_PKEY_encrypt).
    openssl_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new(receiver_key.get(), nullptr), EVP_PKEY_CTX_free);
    if (!ctx) {
        throw_openssl_error("EVP_PKEY_CTX_new failed");
    }
    if (EVP_PKEY_encrypt_init(ctx.get()) <= 0) {
        throw_openssl_error("EVP_PKEY_encrypt_init failed");
    }

    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outlen, out_session_key.data(),
                         out_session_key.size()) <= 0) {
        throw_openssl_error("EVP_PKEY_encrypt (size) failed");
    }

    HandshakeMessage msg;
    msg.encrypted_session_key.resize(outlen);
    if (EVP_PKEY_encrypt(ctx.get(), msg.encrypted_session_key.data(), &outlen,
                         out_session_key.data(), out_session_key.size()) <= 0) {
        throw_openssl_error("EVP_PKEY_encrypt failed");
    }
    msg.encrypted_session_key.resize(outlen);

    // 4. Подписываем шифртекст приватным ключом отправителя.
    msg.signature = sender.sign(msg.encrypted_session_key);

    return msg;
}

std::vector<unsigned char> process_handshake_request(const RsaKeyPair& receiver,
                                                     const std::string& sender_public_pem,
                                                     const HandshakeMessage& msg) {
    if (!receiver.has_private_key()) {
        throw std::runtime_error("Receiver must have private key for handshake");
    }

    // 1. Загружаем публичный ключ отправителя из PEM-строки.
    openssl_ptr<BIO, decltype(&BIO_free)> mem(
        BIO_new_mem_buf(sender_public_pem.data(),
                        static_cast<int>(sender_public_pem.size())),
        BIO_free);
    if (!mem) {
        throw_openssl_error("BIO_new_mem_buf failed");
    }

    openssl_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> sender_key(
        PEM_read_bio_PUBKEY(mem.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (!sender_key) {
        throw_openssl_error("PEM_read_bio_PUBKEY failed");
    }

    // 2. Проверяем подпись шифртекста, используя публичный ключ отправителя.
    {
        openssl_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdctx(EVP_MD_CTX_new(),
                                                                  EVP_MD_CTX_free);
        if (!mdctx) {
            throw_openssl_error("EVP_MD_CTX_new failed");
        }

        if (EVP_DigestVerifyInit(mdctx.get(), nullptr, EVP_sha256(), nullptr,
                                 sender_key.get()) != 1) {
            throw_openssl_error("EVP_DigestVerifyInit failed");
        }

        if (EVP_DigestVerifyUpdate(mdctx.get(), msg.encrypted_session_key.data(),
                                   msg.encrypted_session_key.size()) != 1) {
            throw_openssl_error("EVP_DigestVerifyUpdate failed");
        }

        int ok = EVP_DigestVerifyFinal(mdctx.get(), msg.signature.data(),
                                       msg.signature.size());
        if (ok != 1) {
            throw std::runtime_error("Handshake signature verification failed");
        }
    }

    // 3. Расшифровываем зашифрованный сеансовый ключ приватным ключом получателя.
    // Из-за инкапсуляции pkey_ в заголовке мы не можем "красиво" достать сырой EVP_PKEY*.
    // Чтобы не усложнять заголовок, реализуем расшифровку через приватный PEM получателя:
    // - экспортируем приватный ключ в PEM-строку
    // - снова загружаем его как EVP_PKEY.
    std::string receiver_priv_pem = receiver.private_pem();
    openssl_ptr<BIO, decltype(&BIO_free)> mem_priv(
        BIO_new_mem_buf(receiver_priv_pem.data(),
                        static_cast<int>(receiver_priv_pem.size())),
        BIO_free);
    if (!mem_priv) {
        throw_openssl_error("BIO_new_mem_buf failed");
    }

    openssl_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> recv_pkey(
        PEM_read_bio_PrivateKey(mem_priv.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (!recv_pkey) {
        throw_openssl_error("PEM_read_bio_PrivateKey failed");
    }

    openssl_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new(recv_pkey.get(), nullptr), EVP_PKEY_CTX_free);
    if (!ctx) {
        throw_openssl_error("EVP_PKEY_CTX_new failed");
    }
    if (EVP_PKEY_decrypt_init(ctx.get()) <= 0) {
        throw_openssl_error("EVP_PKEY_decrypt_init failed");
    }

    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outlen, msg.encrypted_session_key.data(),
                         msg.encrypted_session_key.size()) <= 0) {
        throw_openssl_error("EVP_PKEY_decrypt (size) failed");
    }

    std::vector<unsigned char> session_key(outlen);
    if (EVP_PKEY_decrypt(ctx.get(), session_key.data(), &outlen, msg.encrypted_session_key.data(),
                         msg.encrypted_session_key.size()) <= 0) {
        throw_openssl_error("EVP_PKEY_decrypt failed");
    }
    session_key.resize(outlen);

    return session_key;
}

}  // namespace crypto

