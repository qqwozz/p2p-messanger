#include "crypto/crypto.hpp"

#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

using namespace crypto;

// Небольшая утилита для преобразования std::string в вектор байт.
static std::vector<unsigned char> to_bytes(const std::string& s) {
    return std::vector<unsigned char>(s.begin(), s.end());
}

// И обратно: из байтов в строку (для удобного вывода).
static std::string to_string(const std::vector<unsigned char>& v) {
    return std::string(v.begin(), v.end());
}

int main() {
    try {
        std::cout << "== RSA key generation (4096 bits) ==\n";
        auto start = std::chrono::steady_clock::now();
        RsaKeyPair alice = RsaKeyPair::generate(4096);
        RsaKeyPair bob = RsaKeyPair::generate(4096);
        auto end = std::chrono::steady_clock::now();
        std::cout << "Keys generated in "
                  << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
                  << " ms\n\n";

        // --- Тест сохранения/загрузки PEM ---
        std::cout << "== PEM save/load test ==\n";
        alice.save_private_pem("alice_private.pem");
        alice.save_public_pem("alice_public.pem");

        auto alice_priv_loaded = RsaKeyPair::load_private_pem("alice_private.pem");
        auto alice_pub_loaded = RsaKeyPair::load_public_pem("alice_public.pem");

        std::string test_msg = "hello pem";
        auto sig = alice_priv_loaded.sign(to_bytes(test_msg));
        bool ok = alice_pub_loaded.verify(to_bytes(test_msg), sig);
        std::cout << "PEM roundtrip signature verify: " << (ok ? "OK" : "FAIL") << "\n\n";

        // --- Тест AES-256-GCM шифрования ---
        std::cout << "== AES-256-GCM encrypt/decrypt test ==\n";
        std::vector<unsigned char> aes_key(32, 0x11);  // простой "ключ" из одинаковых байт
        std::string plaintext = "Привет, мир! This is a test message.";
        auto aad = to_bytes("header-data");

        auto enc = aes256_gcm_encrypt(aes_key, to_bytes(plaintext), aad);
        auto dec = aes256_gcm_decrypt(aes_key, enc, aad);

        std::cout << "Plaintext:  " << plaintext << "\n";
        std::cout << "Decrypted:  " << to_string(dec) << "\n";
        std::cout << "AES encrypt/decrypt: " << ((plaintext == to_string(dec)) ? "OK" : "FAIL")
                  << "\n\n";

        // Попробуем умышленно испортить тег и убедиться, что проверка целостности срабатывает.
        std::cout << "== AES-256-GCM integrity check test ==\n";
        auto tampered = enc;
        if (!tampered.tag.empty()) {
            tampered.tag[0] ^= 0xFF;  // инвертируем один байт тега
        }

        bool auth_failed = false;
        try {
            auto _ = aes256_gcm_decrypt(aes_key, tampered, aad);
            (void)_;
        } catch (const std::exception&) {
            auth_failed = true;
        }

        std::cout << "AES-GCM tamper detection: " << (auth_failed ? "OK" : "FAIL") << "\n\n";
        if (!auth_failed) {
            std::cerr << "AES-GCM integrity test FAILED\n";
            return 1;
        }

        // --- Тест подписи и проверки ---
        std::cout << "== RSA sign/verify test ==\n";
        std::string msg = "Message to sign";
        auto msg_bytes = to_bytes(msg);

        auto signature = alice.sign(msg_bytes);
        bool valid = alice.verify(msg_bytes, signature);
        std::cout << "Self-verify: " << (valid ? "OK" : "FAIL") << "\n";

        bool valid_by_pub = alice_pub_loaded.verify(msg_bytes, signature);
        std::cout << "Verify by loaded public key: " << (valid_by_pub ? "OK" : "FAIL") << "\n\n";

        // Проверяем, что подпись по испорченным данным НЕ проходит.
        std::cout << "== RSA tampered signature test ==\n";
        auto bad_sig = signature;
        if (!bad_sig.empty()) {
            bad_sig[0] ^= 0xFF;  // искажаем подпись
        }
        bool tampered_ok = alice_pub_loaded.verify(msg_bytes, bad_sig);
        std::cout << "Verify tampered signature: " << (tampered_ok ? "OK" : "EXPECTED FAIL") << "\n\n";
        if (tampered_ok) {
            std::cerr << "Tampered signature verification unexpectedly succeeded\n";
            return 1;
        }

        // --- Тест handshake ---
        std::cout << "== Handshake test (Alice -> Bob) ==\n";
        std::vector<unsigned char> alice_session_key;
        auto bob_public_pem = bob.public_pem();
        auto alice_public_pem = alice.public_pem();

        auto hs_msg = create_handshake_request(alice, bob_public_pem, alice_session_key);
        auto bob_session_key =
            process_handshake_request(bob, alice_public_pem, hs_msg);

        bool same_key = (alice_session_key == bob_session_key);
        std::cout << "Session keys equal: " << (same_key ? "YES" : "NO") << "\n\n";

        // --- Тест производительности ---
        std::cout << "== Performance test ==\n";
        const int aes_iters = 10000;
        const int rsa_iters = 500;

        std::vector<unsigned char> perf_plain(1024, 0x42);  // 1 КБ данных

        start = std::chrono::steady_clock::now();
        AesGcmCiphertext last_bundle;
        for (int i = 0; i < aes_iters; ++i) {
            last_bundle = aes256_gcm_encrypt(aes_key, perf_plain);
        }
        end = std::chrono::steady_clock::now();
        auto aes_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        std::cout << "AES-256-GCM " << aes_iters << " encryptions of 1KB: "
                  << aes_ms << " ms\n";

        start = std::chrono::steady_clock::now();
        for (int i = 0; i < rsa_iters; ++i) {
            auto tmp_sig = alice.sign(perf_plain);
            (void)tmp_sig;
        }
        end = std::chrono::steady_clock::now();
        auto rsa_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        std::cout << "RSA-4096 " << rsa_iters << " signatures: "
                  << rsa_ms << " ms\n";

        std::cout << "\nAll tests completed.\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}

