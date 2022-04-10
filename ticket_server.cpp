#include <iostream>
#include <string>
#include <sstream>
#include <chrono>
#include <vector>
#include <exception>
#include <algorithm>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <tuple>
#include <random>
#include <functional>
#include <limits>
#include <cassert>
#include <bitset>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <endian.h>
#include <unistd.h>

#ifdef NDEBUG
const bool DEBUG = true;
#else
const bool DEBUG = false;
#endif

using message_id_t = uint8_t;
using description_length_t = uint8_t;
using ticket_count_t = uint16_t;
using event_id_t = uint32_t;
using reservation_id_t = uint32_t;
using expiration_time_t = uint64_t;
using cookie_t = std::vector<char>;

const uint16_t DEFAULT_SERVER_PORT = 2022;
const expiration_time_t DEFAULT_TIMEOUT = 5;
const size_t TICKET_SIZE = 7;
const size_t COOKIE_SIZE = 48;
const size_t TICKETS_RESPONSE_HEADER_SIZE = sizeof(reservation_id_t) + sizeof(ticket_count_t);
const size_t GET_EVENTS_REQUEST_SIZE = sizeof(message_id_t);
const size_t GET_RESERVATION_REQUEST_SIZE = sizeof(message_id_t) + sizeof(event_id_t) + sizeof(ticket_count_t);
const size_t GET_TICKETS_REQUEST_SIZE = sizeof(message_id_t) + sizeof(reservation_id_t) + COOKIE_SIZE;
const int BUFFER_SIZE = 65507;                   // max UDP size
const size_t DEBUG_MAX_RECEIVE_BYTES_PRINT = 20; // gets printed in server.listen()

enum class request_type_t : message_id_t
{
    GET_EVENTS = 1,
    EVENTS = 2,
    GET_RESERVATION = 3,
    RESERVATION = 4,
    GET_TICKETS = 5,
    TICKETS = 6,
    BAD_REQUEST = 255,
};

std::tuple<std::string, uint16_t, expiration_time_t> pase_arguments(const int argc, const char *argv[]);

class TicketMenager
{
private:
    struct __attribute__((__packed__)) Ticket
    {
        char data[TICKET_SIZE];

        std::string to_string()
        {
            std::string result(data);
            return result;
        }
    };

    class TicketReservation
    {
    private:
        mutable bool is_picked_up;
        std::chrono::system_clock::time_point time_created;
        int64_t timeout;
        std::vector<Ticket> tickets;
        std::function<void(void)> restore_tickets;

        Ticket generate_ticket(std::mt19937 &random_state_ref) const noexcept
        {
            static std::unordered_set<std::string> tickets_in_use;
            Ticket ticket;

            do
            {

                for (size_t i = 0; i < TICKET_SIZE; i++)
                {
                    if (random_state_ref() % 3 == 0)
                        ticket.data[i] = '0' + random_state_ref() % 10;
                    else
                        ticket.data[i] = 'A' + random_state_ref() % 26;
                }
            } while (tickets_in_use.find(ticket.to_string()) != tickets_in_use.end());
            tickets_in_use.insert(ticket.to_string());
            return ticket;
        }

    public:
        TicketReservation(ticket_count_t ticket_count, int64_t timeout, std::mt19937 &random_state_ref, std::function<void(void)> restore_tickets)
            : is_picked_up(false), time_created(std::chrono::system_clock::now()),
              timeout(timeout), restore_tickets(restore_tickets)
        {
            for (auto i = 0; i < ticket_count; i++)
                tickets.push_back(generate_ticket(random_state_ref));
        }

        ~TicketReservation()
        {
            restore_tickets();
        }

        expiration_time_t get_expiration_time() const noexcept
        {
            return std::chrono::duration_cast<std::chrono::seconds>(
                       time_created.time_since_epoch() + std::chrono::seconds(timeout))
                .count();
        }

        ticket_count_t get_ticket_count() const noexcept
        {
            return tickets.size();
        }

        const std::vector<Ticket> &get_tickets() const noexcept
        {
            return tickets;
        }

        bool is_valid() const noexcept
        {
            if (is_picked_up)
                return true;
            std::chrono::system_clock::time_point time_now = std::chrono::system_clock::now();
            auto diff = std::chrono::duration_cast<std::chrono::seconds>(time_now - time_created).count();
            return diff < timeout;
        }

        void pick_up() const noexcept
        {
            is_picked_up = true;
        }
    };

    cookie_t get_reservation_cookie(reservation_id_t reservation_id)
    {
        cookie_t cookie(COOKIE_SIZE);
        srand(reservation_id);
        for (char &c : cookie)
            c = rand() % (126 - 33) + 33;

        return cookie;
    }

    reservation_id_t generate_reservation_id()
    {
        static const reservation_id_t min_reservation_id = 1000000;
        reservation_id_t new_id;
        do
        {
            new_id = random_state() % (std::numeric_limits<reservation_id_t>::max() - min_reservation_id) + min_reservation_id;
        } while (reservations_umap.find(new_id) != reservations_umap.end());

        return new_id;
    }

    uint64_t timeout;
    std::unordered_multimap<std::string, event_id_t> descrition_to_event_id_map; // next event id = next available id starting from 0
    std::unordered_map<event_id_t, ticket_count_t> event_id_to_tickets_count_map;
    std::unordered_map<reservation_id_t, TicketReservation> reservations_umap;
    std::mt19937 random_state;

public:
    TicketMenager(std::string file_path, uint64_t timeout)
        : timeout(timeout)
    {
        // we assume that the file is correct
        std::ifstream file;
        std::string event_name;
        file.open(file_path);

        while (std::getline(file, event_name))
        {
            std::string tmp;
            getline(file, tmp);
            ticket_count_t ticket_count = std::stoi(tmp);
            event_id_t event_id = descrition_to_event_id_map.size();

            descrition_to_event_id_map.insert({event_name, event_id});
            event_id_to_tickets_count_map.insert({event_id, ticket_count});
        }

        file.close();
    }

    void check_reservation_timeouts()
    {
        for (auto reservation_it = reservations_umap.cbegin(); reservation_it != reservations_umap.cend();)
        {
            if (!reservation_it->second.is_valid())
                reservations_umap.erase(reservation_it++);
            else
                ++reservation_it;
        }
    }

    std::vector<std::tuple<std::string, event_id_t, ticket_count_t>> get_events()
    {
        check_reservation_timeouts();

        std::vector<std::tuple<std::string, event_id_t, ticket_count_t>> events;
        std::for_each(
            descrition_to_event_id_map.begin(),
            descrition_to_event_id_map.end(),
            [&](auto event)
            {
                events.push_back({event.first, event.second, event_id_to_tickets_count_map[event.second]});
            });

        return events;
    }

    std::tuple<reservation_id_t, cookie_t, expiration_time_t> create_reservation(event_id_t event_id, ticket_count_t ticket_count)
    {
        size_t tickets_size = ticket_count * sizeof(Ticket);
        if (ticket_count == 0 || tickets_size + TICKETS_RESPONSE_HEADER_SIZE > BUFFER_SIZE)
            throw std::runtime_error("ticket reservation error! invalid ticket count");

        auto event_it = event_id_to_tickets_count_map.find(event_id);
        if (event_it == event_id_to_tickets_count_map.end())
            throw std::runtime_error("ticket reservation error! no such event");
        else if (event_it->second < ticket_count)
            check_reservation_timeouts();

        event_it = event_id_to_tickets_count_map.find(event_id);
        if (event_it->second < ticket_count)
        {
            throw std::runtime_error("ticket reservation error! no free tickets");
        }
        else
            event_it->second -= ticket_count;

        auto ticket_resore_callback = [event_id, ticket_count, &event_map = event_id_to_tickets_count_map]() mutable
        {
            event_map[event_id] += ticket_count;
        };

        reservation_id_t reservation_id = generate_reservation_id();
        auto new_reservation = reservations_umap.emplace(std::piecewise_construct, std::forward_as_tuple(reservation_id), std::forward_as_tuple(ticket_count, timeout, random_state, ticket_resore_callback));
        cookie_t cookie = get_reservation_cookie(reservation_id);
        expiration_time_t expiration_time = new_reservation.first->second.get_expiration_time();

        return {reservation_id, cookie, expiration_time};
    }

    std::vector<char> get_tickets(reservation_id_t reservation_id, cookie_t cookie)
    {
        if (cookie != get_reservation_cookie(reservation_id))
            throw std::runtime_error("invalid reservation cookie!");

        auto reservation_it = reservations_umap.find(reservation_id);
        if (reservation_it == reservations_umap.end())
            throw std::runtime_error("no such reservation!");
        else
        {
            if (!reservation_it->second.is_valid())
            {
                reservations_umap.erase(reservation_it);
                throw std::runtime_error("reservation has expired!");
            }
            else
                reservation_it->second.pick_up();
        }

        const std::vector<Ticket> &tickets = reservation_it->second.get_tickets();
        std::vector<char> encoded_tickets(sizeof(Ticket) * tickets.size());

        for (size_t i = 0; i < tickets.size(); i++)
        {
            for (size_t j = 0; j < sizeof(Ticket); j++)
                encoded_tickets[i * sizeof(Ticket) + j] = *(((char *)&tickets[i]) + j);
        }

        return encoded_tickets;
    }
};

class TicketServer
{
private:
    TicketMenager ticket_menager;
    uint16_t port;
    uint64_t timeout;
    char buffer[BUFFER_SIZE];
    int socket_fd;

    struct __attribute__((__packed__)) EventResponse
    {
        event_id_t event_id;
        ticket_count_t ticket_count;
        description_length_t description_length;
        // description is copied by memcpy
    };

    struct __attribute__((__packed__)) ReservationResponse
    {
        reservation_id_t reservation_id;
        event_id_t event_id;
        ticket_count_t ticket_count;
        char cookie[48] = {'\0'}; // default value to disable missing initialization warning
        expiration_time_t expiration_time;
    };

    size_t read_message(struct sockaddr_in *client_address)
    {
        socklen_t address_length = (socklen_t)sizeof(*client_address);
        int flags = 0;
        ssize_t len = recvfrom(socket_fd, buffer, sizeof(buffer), flags,
                               (struct sockaddr *)client_address, &address_length);

        if (len < 0)
        {
            std::cerr << "error in recvfrom "
                      << "errno code:  " << strerror(errno) << " " << errno;
            return 0;
        }

        return (size_t)len;
    }

    void send_message(struct sockaddr_in *client_address, size_t length)
    {
        socklen_t address_length = (socklen_t)sizeof(*client_address);
        int flags = 0;
        ssize_t sent_length = sendto(socket_fd, buffer, length, flags,
                                     (struct sockaddr *)client_address, address_length);
        if (sent_length != (ssize_t)length)
        {
            std::cerr << "error in sendto "
                      << "errno code:  " << strerror(errno) << " errno : " << errno;
        }
    }

    size_t handle_get_events(size_t read_length)
    {
        if (read_length != GET_EVENTS_REQUEST_SIZE)
            return 0;

        if (DEBUG)
            std::cerr << "got GET_EVENTS, ";

        buffer[0] = (message_id_t)request_type_t::EVENTS;

        auto events = ticket_menager.get_events();

        size_t how_many_to_send = 0;
        int free_space = BUFFER_SIZE - sizeof(message_id_t);
        for (auto &event : events)
        {
            free_space -= sizeof(EventResponse);
            free_space -= std::get<0>(event).length();

            if (free_space >= 0)
                how_many_to_send++;
            else
                break;
        }

        size_t buffer_index = 1;
        for (size_t i = 0; i < how_many_to_send; i++)
        {
            std::string event_desc = std::get<0>(events[i]);

            struct EventResponse event_response
            {
                .event_id = htonl(std::get<1>(events[i])),
                .ticket_count = htons(std::get<2>(events[i])),
                .description_length = (uint8_t)event_desc.length(),
            };

            memcpy(buffer + buffer_index, &event_response, sizeof(event_response));
            buffer_index += sizeof(event_response);
            memcpy(buffer + buffer_index, event_desc.c_str(), sizeof(char) * event_response.description_length);
            buffer_index += sizeof(char) * event_response.description_length;
        }

        return buffer_index;
    }

    size_t handle_get_reservation(size_t read_length)
    {
        if (read_length != GET_RESERVATION_REQUEST_SIZE)
            return 0;

        event_id_t event_id = ntohl(*(event_id_t *)(buffer + 1));
        ticket_count_t ticket_count = ntohs(*(ticket_count_t *)(buffer + sizeof(event_id_t) + 1));

        reservation_id_t reservation_id;
        cookie_t cookie;
        expiration_time_t expiration_time;

        if (DEBUG)
            std::cerr << "got GET_RESERVATION, ";

        try
        {
            std::tie(reservation_id, cookie, expiration_time) = ticket_menager.create_reservation(event_id, ticket_count);
        }
        catch (const std::exception &e)
        {
            if (DEBUG)
                std::cerr << e.what() << '\n';
            buffer[0] = (message_id_t)request_type_t::BAD_REQUEST;
            // event id is not hanged since reciving message so we do not have to set it
            return 1 + sizeof(event_id_t);
        }

        struct ReservationResponse reservation_response
        {
            .reservation_id = htonl(reservation_id),
            .event_id = htonl(event_id),
            .ticket_count = htons(ticket_count),
            .expiration_time = htobe64(expiration_time)
        };
        memcpy(reservation_response.cookie, cookie.data(), COOKIE_SIZE);

        buffer[0] = (message_id_t)request_type_t::RESERVATION;
        memcpy(buffer + sizeof(message_id_t), &reservation_response, sizeof(reservation_response));

        if (DEBUG)
        {
            std::cerr << " reservation data: id: " << reservation_id << ", cookie: ";
            for (auto c : cookie)
                std::cerr << c;
            std::cerr << ", expiration time: " << expiration_time << " ";
        }

        return sizeof(reservation_response) + sizeof(message_id_t);
    }

    size_t handle_get_tickets(size_t read_length)
    {
        if (read_length != GET_TICKETS_REQUEST_SIZE)
            return 0;

        // reservation_id, cookie
        reservation_id_t reservation_id = ntohl(*(reservation_id_t *)(buffer + 1));
        cookie_t cookie(buffer + 1 + sizeof(reservation_id), buffer + 1 + sizeof(reservation_id) + COOKIE_SIZE);

        if (DEBUG)
        {
            std::cerr << "got GET_TICKETS, id: " << reservation_id << ", cookie: ";
            for (auto c : cookie)
                std::cerr << c;
            std::cerr << " ";
        }

        std::vector<char> tickets;
        try
        {
            // note: tickets are already splitted into chars
            tickets = ticket_menager.get_tickets(reservation_id, cookie);
        }
        catch (const std::exception &e)
        {
            if (DEBUG)
                std::cerr << e.what() << '\n';
            buffer[0] = (message_id_t)request_type_t::BAD_REQUEST;
            // reservation id is not hanged since reciving message so we do not have to set it
            return 1 + sizeof(reservation_id_t);
        }

        buffer[0] = (message_id_t)request_type_t::TICKETS;
        // reservation id is not changed since reciving message so we do not have to set it
        // ticket_count_t ticket_count_net_order = htons(tickets.size() / TICKET_SIZE);
        ticket_count_t ticket_count_net_order = tickets.size() / TICKET_SIZE;
        buffer[sizeof(message_id_t) + sizeof(reservation_id)] = (uint8_t)((ticket_count_net_order >> 8) & 0xff);
        buffer[sizeof(message_id_t) + sizeof(reservation_id) + 1] = (uint8_t)(ticket_count_net_order & 0xff);

        memcpy(buffer + sizeof(message_id_t) + sizeof(reservation_id) + sizeof(ticket_count_t),
               tickets.data(),
               tickets.size());

        return sizeof(message_id_t) + sizeof(reservation_id) + sizeof(ticket_count_t) + tickets.size();
    }

    size_t handle_request(size_t read_length)
    {
        request_type_t request_type{(message_id_t)buffer[0]};
        size_t response_len = 0;

        switch (request_type)
        {
        case request_type_t::GET_EVENTS:
            response_len = handle_get_events(read_length);
            break;
        case request_type_t::GET_RESERVATION:
            response_len = handle_get_reservation(read_length);
            break;
        case request_type_t::GET_TICKETS:
            response_len = handle_get_tickets(read_length);
            break;
        default:
            if (DEBUG)
                std::cerr << "Incorrect message_id: " << (message_id_t)buffer[0] << " no response sent \n";
            break;
        }

        return response_len;
    }

public:
    TicketServer(std::string file_path, uint16_t port, uint64_t timeout)
        : ticket_menager(file_path, timeout), port(port), timeout(timeout)
    {
        memset(buffer, 0, sizeof(buffer));
        // socket binding
        socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd <= 0)
        {
            std::cerr << "Unable to start server on specified port! errno code:  " << strerror(errno) << " " << errno;
            exit(1);
        }

        struct sockaddr_in server_address;
        server_address.sin_family = AF_INET;                // IPv4
        server_address.sin_addr.s_addr = htonl(INADDR_ANY); // listening on all interfaces
        server_address.sin_port = htons(port);

        if (bind(socket_fd, (struct sockaddr *)&server_address,
                 (socklen_t)sizeof(server_address)) != 0)
        {
            std::cerr << "Unable to start server on specified port! errno code:  " << strerror(errno) << " " << errno;
            exit(1);
        }

        if (DEBUG)
        {
            std::cerr << "Succeeded to start server on port: " << port << "\n";
        }
    }

    ~TicketServer()
    {
        close(socket_fd);
    }

    void listen()
    {
        struct sockaddr_in client_address;

        while (true)
        {
            size_t read_length = read_message(&client_address);
            if (read_length == 0)
                continue;
            char *client_ip = inet_ntoa(client_address.sin_addr);
            uint16_t client_port = ntohs(client_address.sin_port);

            if (DEBUG)
            {
                fprintf(stderr, "\nreceived %zd bytes from client %s:%u message: ", read_length, client_ip, client_port);
                std::cerr << " ";
            }

            size_t response_len = handle_request(read_length);
            if (response_len == 0)
                continue;

            if (DEBUG)
                std::cerr << "sending : " << response_len << " bytes\n";

            send_message(&client_address, response_len);
        }
    }
};

int main(const int argc, const char *argv[])
{

    std::string file_path;
    uint16_t port;
    uint64_t timeout;

    try
    {
        std::tie(file_path, port, timeout) = pase_arguments(argc, argv);
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        return 1;
    }

    TicketServer ticket_server(file_path, port, timeout);
    ticket_server.listen();
}

std::tuple<std::string, uint16_t, expiration_time_t> pase_arguments(const int argc, const char *argv[])
{
    std::vector<std::string> args;
    for (int i = 1; i < argc; i++)
        args.push_back(argv[i]);
    std::set<std::string> matched_arguments;

    if (DEBUG)
    {
        std::cerr << "Arguments: ";
        for (auto &s : args)
            std::cerr << "|" << s << "| ";
        std::cerr << "\n";
    }

    if (args.size() != 2 && args.size() != 4 && args.size() != 6)
        throw std::invalid_argument("invalid program's arguments number!");

    std::string file_path;
    uint16_t port = DEFAULT_SERVER_PORT;
    expiration_time_t timeout = DEFAULT_TIMEOUT;

    // process file path argument
    auto it = std::find(args.begin(), args.end(), "-f");
    if (it == args.end() || std::next(it, 1) == args.end() || std::next(it, 1)->length() == 0)
        throw std::invalid_argument("you must specify events file path!");
    else
    {
        matched_arguments.insert(*it++);

        std::ifstream file(*it);
        if (!file.good())
            throw std::invalid_argument("invalid file path!");
        file_path = *it;

        matched_arguments.insert(*it);
    }

    // process port number argument
    it = std::find(args.begin(), args.end(), "-p");
    if (it != args.end() && std::next(it, 1) == args.end())
        throw std::invalid_argument("incorrect port number!");
    else if (it != args.end())
    {
        matched_arguments.insert(*it++);

        errno = 0;
        int maybe_port = stoi(*it, NULL);
        if (maybe_port < 0 || maybe_port > std::numeric_limits<uint16_t>::max() || errno != 0)
            throw std::invalid_argument("invalid port number!");
        port = maybe_port;

        matched_arguments.insert(*it);
    }

    // process timeout argument
    it = std::find(args.begin(), args.end(), "-t");
    if (it != args.end() && std::next(it, 1) == args.end())
        throw std::invalid_argument("incorrect timeout value!");
    else if (it != args.end())
    {
        matched_arguments.insert(*it++);

        std::stringstream maybe_timeout(*it);
        maybe_timeout >> timeout;
        if (timeout < 1 || timeout > 86400)
            throw std::invalid_argument("incorrect timeout range!");

        matched_arguments.insert(*it);
    }

    if (args.size() != matched_arguments.size())
        throw std::invalid_argument("invalid arguments!");
    if (!std::all_of(
            args.begin(),
            args.end(),
            [&](auto argument)
            { return matched_arguments.find(argument) != matched_arguments.end(); }))
        throw std::invalid_argument("invalid arguments!");

    return {file_path, port, timeout};
}