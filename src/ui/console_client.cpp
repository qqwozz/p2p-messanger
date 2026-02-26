#include "network/network.hpp"
#include "network/peer_connection.hpp"
#include "crypto/crypto.hpp"

#include <boost/asio.hpp>

#include <ncurses.h>

#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

// Простейший консольный интерфейс на ncurses.
// Цели:
// - показать базовый UI: список контактов, окно чата и строка ввода;
// - продемонстрировать, как можно "подвесить" к нему сетевую логику;
// - не превращаться в полноценный клиент (минимум кода, максимум понятности).
//
// Сейчас:
// - контакты захардкожены (один "peer");
// - вводимые сообщения сразу же отображаются как "me: ..." и "peer: ..." (эхо-ответ);
// - сеть и криптография подключены, но для простоты не используются.

namespace {

struct UiLayout {
    int width{};
    int height{};
    int contacts_width{};
    int input_height{};
};

UiLayout compute_layout() {
    UiLayout l{};
    getmaxyx(stdscr, l.height, l.width);
    l.contacts_width = l.width / 4;  // 1/4 экрана слева под контакты
    l.input_height = 3;             // 3 строки под ввод
    return l;
}

}  // namespace

int main() {
    // Инициализация ncurses.
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);

    UiLayout layout = compute_layout();

    // Окно для списка контактов.
    WINDOW* contacts_win = newwin(layout.height - layout.input_height, layout.contacts_width, 0, 0);
    box(contacts_win, 0, 0);
    mvwprintw(contacts_win, 0, 2, " Contacts ");
    mvwprintw(contacts_win, 2, 2, "peer");
    wrefresh(contacts_win);

    // Окно для чата.
    WINDOW* chat_win = newwin(layout.height - layout.input_height,
                              layout.width - layout.contacts_width,
                              0,
                              layout.contacts_width);
    box(chat_win, 0, 0);
    mvwprintw(chat_win, 0, 2, " Chat ");
    wrefresh(chat_win);

    // Окно для ввода.
    WINDOW* input_win = newwin(layout.input_height,
                               layout.width,
                               layout.height - layout.input_height,
                               0);
    box(input_win, 0, 0);
    mvwprintw(input_win, 0, 2, " Input (/quit, /help) ");
    wrefresh(input_win);

    // История сообщений для отображения в chat_win.
    std::vector<std::string> history;

    auto redraw_chat = [&]() {
        werase(chat_win);
        box(chat_win, 0, 0);
        mvwprintw(chat_win, 0, 2, " Chat ");

        int max_lines = layout.height - layout.input_height - 2;  // внутри рамки
        int start = 0;
        if ((int)history.size() > max_lines) {
            start = (int)history.size() - max_lines;
        }
        int y = 1;
        for (int i = start; i < (int)history.size(); ++i) {
            mvwprintw(chat_win, y++, 1, "%s", history[i].c_str());
        }
        wrefresh(chat_win);
    };

    bool running = true;
    while (running) {
        // Очищаем строку ввода.
        werase(input_win);
        box(input_win, 0, 0);
        mvwprintw(input_win, 0, 2, " Input (/quit, /help) ");
        mvwprintw(input_win, 1, 2, "> ");
        wmove(input_win, 1, 4);
        wrefresh(input_win);

        char buffer[512];
        wgetnstr(input_win, buffer, sizeof(buffer) - 1);
        std::string line(buffer);

        if (line == "/quit") {
            running = false;
            break;
        }
        if (line == "/help") {
            history.push_back("[system] commands: /quit, /help");
            redraw_chat();
            continue;
        }

        if (line.empty()) {
            continue;
        }

        // В реальном приложении здесь бы:
        // - шифровали сообщение через crypto::aes256_gcm_encrypt;
        // - отправляли через PeerConnection::sendEncryptedMessage;
        // - принимали бы входящие через handleIncomingPacket и добавляли в историю.

        // Пока просто показываем отправку и "ответ" пира.
        history.push_back("me: " + line);
        history.push_back("peer: (echo) " + line);
        redraw_chat();
    }

    // Завершаем ncurses.
    delwin(contacts_win);
    delwin(chat_win);
    delwin(input_win);
    endwin();

    return 0;
}

