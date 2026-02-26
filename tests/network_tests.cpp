#include "network/network.hpp"

#include <boost/asio.hpp>

#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

int main() {
    try {
        std::cout << "== UDP basic test (localhost) ==\n";

        boost::asio::io_context io;

        // Создаём два UDP endpoint'а на localhost с произвольными портами.
        network::UdpEndpoint a(io, 0);
        network::UdpEndpoint b(io, 0);

        auto a_port = a.local_port();
        auto b_port = b.local_port();

        std::cout << "A port: " << a_port << ", B port: " << b_port << "\n";

        boost::asio::ip::udp::endpoint endpoint_a(
            boost::asio::ip::address::from_string("127.0.0.1"), a_port);
        boost::asio::ip::udp::endpoint endpoint_b(
            boost::asio::ip::address::from_string("127.0.0.1"), b_port);

        // --- Проверяем сериализацию/десериализацию пакета ---
        network::Packet p_out;
        p_out.type = network::PacketType::Data;
        p_out.seq = 42;
        std::string msg = "hello over udp";
        p_out.payload.assign(msg.begin(), msg.end());

        auto raw = network::serialize_packet(p_out);
        auto p_parsed = network::parse_packet(raw.data(), raw.size());

        if (p_parsed.type != p_out.type || p_parsed.seq != p_out.seq ||
            std::string(p_parsed.payload.begin(), p_parsed.payload.end()) != msg) {
            std::cerr << "Packet (de)serialization FAILED\n";
            return 1;
        }
        std::cout << "Packet (de)serialization OK\n";

        // --- Отправляем пакет от A к B и проверяем доставку ---
        a.send_to(raw, endpoint_b);

        std::vector<std::uint8_t> buf;
        boost::asio::ip::udp::endpoint sender;
        bool got = b.receive_from(buf, sender, 500ms);

        if (!got) {
            std::cerr << "Did not receive UDP packet on B\n";
            return 1;
        }

        auto recv = network::parse_packet(buf.data(), buf.size());
        std::string recv_msg(recv.payload.begin(), recv.payload.end());

        std::cout << "Received on B from " << sender.address().to_string()
                  << ":" << sender.port() << " -> \"" << recv_msg << "\"\n";

        if (recv_msg != msg) {
            std::cerr << "Payload mismatch\n";
            return 1;
        }

        // --- Локальная имитация hole punching (оба на localhost) ---
        std::cout << "== UDP hole punching (localhost simulation) ==\n";

        bool a_ok = false;
        bool b_ok = false;

        std::thread th_a([&] {
            a_ok = network::udp_hole_punch(a, endpoint_b, 200ms, 5);
        });
        std::thread th_b([&] {
            b_ok = network::udp_hole_punch(b, endpoint_a, 200ms, 5);
        });

        th_a.join();
        th_b.join();

        std::cout << "A hole_punch result: " << (a_ok ? "OK" : "FAIL") << "\n";
        std::cout << "B hole_punch result: " << (b_ok ? "OK" : "FAIL") << "\n";

        if (!a_ok || !b_ok) {
            std::cerr << "Hole punching simulation failed\n";
            return 1;
        }

        // --- Проверка keep-alive: просто убеждаемся, что цикл запускается и прекращается ---
        std::cout << "== Keep-alive loop test ==\n";
        std::atomic_bool stop_flag{false};
        std::thread ka_thread([&] {
            network::keep_alive_loop(a, endpoint_b, 1s, stop_flag);
        });

        std::this_thread::sleep_for(3s);
        stop_flag.store(true);
        ka_thread.join();

        std::cout << "All network tests completed.\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}

