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
#include <memory>
#include <random>
#include <functional>
#include <limits>
#include <cassert>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <endian.h>

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
const size_t DEBUG_MAX_MESSAGE_PRINT_LEN = 100;
const size_t COOKIE_SIZE = 48;
const size_t TICKETS_RESPONSE_HEADER_SIZE = sizeof(reservation_id_t) + sizeof(ticket_count_t);

const int BUFFER_SIZE = 65527;

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
    };

    class TicketReservation
    {
    private:
        reservation_id_t reservation_id;
        std::vector<Ticket> tickets;
        expiration_time_t expiration_time;
        bool is_picked_up;
        std::function<void(void)> restore_tickets;

        Ticket generate_ticket(std::mt19937 &random_state_ref)
        {
            Ticket ticket;
            for (size_t i = 0; i < TICKET_SIZE; i++)
            {
                if (random_state_ref() % 2 == 0)
                    ticket.data[i] = 'a' + random_state_ref() % 26;
                else
                    ticket.data[i] = '0' + random_state_ref() % 10;
            }
            return ticket;
        }

    public:
        TicketReservation(ticket_count_t ticket_count, std::mt19937 &random_state_ref, std::function<void(void)> restore_tickets)
            : is_picked_up(false), restore_tickets(restore_tickets)
        {
            reservation_id = random_state_ref() % (std::numeric_limits<reservation_id_t>::max() - 999999) + 999999;

            tickets.resize(ticket_count);
            for (auto i = 0; i < ticket_count; i++)
                tickets[i] = generate_ticket(random_state_ref);

            uint64_t time_now = time(NULL);
            expiration_time = time_now + DEFAULT_TIMEOUT;
        }

        ~TicketReservation()
        {
            // std::cerr << " destructor of reservation " << reservation_id << " ";
            restore_tickets();
        }

        reservation_id_t get_reservation_id() const
        {
            return this->reservation_id;
        }

        expiration_time_t get_expiration_time() const
        {
            return this->expiration_time;
        }

        ticket_count_t get_ticket_count() const
        {
            return tickets.size();
        }

        bool is_valid() const
        {
            if (is_picked_up)
                return true;
            uint64_t time_now = time(NULL);
            // if(DEBUG)
            // {
            //     std::cerr << "time now : " << time_now << " expiration time : "<< expiration_time << " difference " <<time_now - expiration_time << "\n";
            // }
            return time_now < expiration_time;
        }

        void pick_up()
        {
            is_picked_up = true;
        }

        [[maybe_unused]] friend std::ostream &operator<<(std::ostream &os, const std::unique_ptr<TicketReservation> &ticket_reservation)
        {
            os << "RESERVATION: " << ticket_reservation->reservation_id << " tickets: ";
            for (auto &t : ticket_reservation->tickets)
                os << t.data << ", ";

            return os;
        }

        bool operator==(const TicketReservation &other) const
        {
            return this->reservation_id == other.reservation_id;
        }
    };

    // https://stackoverflow.com/questions/32613304/find-a-value-in-an-unordered-set-of-shared-ptr
    struct Deref
    {
        struct Hash
        {
            std::size_t operator()(std::unique_ptr<TicketReservation> const &p) const
            {
                return std::hash<reservation_id_t>()(p->get_reservation_id());
            }
        };

        struct Compare
        {
            size_t operator()(reservation_id_t const reservation_id,
                              std::unique_ptr<TicketReservation> const &b) const
            {
                return reservation_id == b.get()->get_reservation_id();
            }
        };
    };

    cookie_t get_reservation_cookie(reservation_id_t reservation_id)
    {
        cookie_t cookie(COOKIE_SIZE);
        srand(reservation_id);
        for (char &c : cookie)
            c = rand() % (126 - 33) + 33;

        return cookie;
    }

    std::unordered_map<std::string, event_id_t> descrition_to_event_id_map; // next event id = next available id starting from 0
    std::unordered_map<event_id_t, ticket_count_t> event_id_to_tickets_count_map;
    std::unordered_set<std::unique_ptr<TicketReservation>, Deref::Hash, Deref::Compare> reservations_set;
    std::mt19937 random_state;

public:
    TicketMenager(std::string file_path)
    {
        // we assume that the file is correct
        std::ifstream file;
        std::string event_name;
        file.open(file_path);

        while (std::getline(file, event_name))
        {
            std::string tmp;
            getline(file, tmp);
            std::cerr << event_name << " " << tmp << "\n";
            ticket_count_t ticket_count = std::stoi(tmp);
            event_id_t event_id = descrition_to_event_id_map.size();

            descrition_to_event_id_map.insert({event_name, event_id});
            event_id_to_tickets_count_map.insert({event_id, ticket_count});
        }

        file.close();
    }

    void check_reservation_timeouts()
    {
        for (auto reservation_it = reservations_set.cbegin(); reservation_it != reservations_set.cend();)
        {
            if (!reservation_it->get()->is_valid())
                reservations_set.erase(reservation_it++);
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

        if (DEBUG)
        {
            std::cerr << "Events and free tickets: ";
            for (auto p : events)
            {
                std::cerr << std::get<0>(p) << " :" << std::get<1>(p) << " " << std::get<2>(p) << ", ";
            }
            std::cerr << "\n";
        }

        return events;
    }

    std::tuple<reservation_id_t, cookie_t, expiration_time_t> create_reservation(event_id_t event_id, ticket_count_t ticket_count)
    {
        size_t ticket_size = ticket_count * sizeof(Ticket);
        if (ticket_count == 0 || ticket_size + TICKETS_RESPONSE_HEADER_SIZE > BUFFER_SIZE)
            throw std::runtime_error("ticket reservation error! invalid ticket count");

        auto event_it = event_id_to_tickets_count_map.find(event_id);
        if(event_it == event_id_to_tickets_count_map.end())
            throw std::runtime_error("ticket reservation error! no such event");
        else if (event_it->second < ticket_count)
            check_reservation_timeouts();

        event_it = event_id_to_tickets_count_map.find(event_id);
        if (DEBUG)  
                std::cerr << "ticket count: " << event_it->second << " ";
        if (event_it->second < ticket_count)
        {
            throw std::runtime_error("ticket reservation error! no free tickets");
        }
        else
            event_it->second -= ticket_count;

        auto ticket_resore_callback = [event_id, ticket_count, &event_map = event_id_to_tickets_count_map]() mutable
        {
            if (DEBUG)
                std::cerr << "restore " << ticket_count << " to event id " << event_id<<"\n";
            event_map[event_id] += ticket_count;
        };

        auto new_reservation = reservations_set.emplace(std::make_unique<TicketReservation>(ticket_count, random_state, ticket_resore_callback));
        reservation_id_t reservation_id = new_reservation.first->get()->get_reservation_id();
        cookie_t cookie = get_reservation_cookie(reservation_id);
        expiration_time_t expiration_time = new_reservation.first->get()->get_expiration_time();

        return {reservation_id, cookie, expiration_time};
    }

    std::vector<char> get_tickets(reservation_id_t reservation_id, std::vector<char> cookie)
    {
        // auto reservation_it = reservations_set.find(reservation_id);

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

    struct __attribute__((__packed__)) ReservationResponse
    {
        // reservation_id, event_id, ticket_count, cookie, expiration_time
        reservation_id_t reservation_id;
        event_id_t event_id;
        ticket_count_t ticket_count;
        char cookie[COOKIE_SIZE];
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

    size_t handle_get_events()
    {
        if (DEBUG)
            std::cerr << "got GET_EVENTS, ";

        buffer[0] = (message_id_t)request_type_t::EVENTS;

        auto events = ticket_menager.get_events();

        size_t how_many_to_send = 0;
        int free_space = BUFFER_SIZE - 1;
        for (auto &event : events)
        {
            free_space -= sizeof(event_id_t);
            free_space -= sizeof(ticket_count_t);
            free_space -= sizeof(uint8_t);
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
            // event_id_t event_id = htonl(std::get<1>(events[i]));
            // ticket_count_t ticket_count = htons(std::get<2>(events[i]));
            event_id_t event_id = std::get<1>(events[i]);
            ticket_count_t ticket_count = std::get<2>(events[i]);

            // order : event_id, ticket_count, description_length, description,
            buffer[buffer_index++] = (uint8_t)((event_id >> 24) & 0xff);
            buffer[buffer_index++] = (uint8_t)((event_id >> 16) & 0xff);
            buffer[buffer_index++] = (uint8_t)((event_id >> 8) & 0xff);
            buffer[buffer_index++] = (uint8_t)(event_id & 0xff);

            buffer[buffer_index++] = (uint8_t)((ticket_count >> 8) & 0xff);
            buffer[buffer_index++] = (uint8_t)(ticket_count & 0xff);

            buffer[buffer_index++] = (uint8_t)(event_desc.length() & 0xff);
            for (char c : event_desc)
                buffer[buffer_index++] = c;
        }

        return buffer_index;
    }

    size_t handle_get_reservation()
    {
        if (DEBUG)
            std::cerr << "got GET_RESERVATION, ";
        // event_id, ticket_count
        event_id_t event_id = ntohl(*(event_id_t *)(buffer + 1));
        ticket_count_t ticket_count = ntohs(*(ticket_count_t *)(buffer + sizeof(event_id_t) + 1));

        // reservation_id, event_id, ticket_count, cookie, expiration_time
        reservation_id_t reservation_id;
        cookie_t cookie;
        expiration_time_t expiration_time;

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

        struct ReservationResponse response
        {
            .reservation_id = htonl(reservation_id),
            .event_id = htonl(event_id),
            .ticket_count = htons(ticket_count),
            .expiration_time = htobe64(expiration_time)
        };

        for (size_t i = 0; i < COOKIE_SIZE; i++)
            response.cookie[i] = cookie[i];

        size_t size = sizeof(response);
        char *pchar = (char *)&response;

        buffer[0] = (message_id_t)request_type_t::RESERVATION;
        for (size_t i = 0; i < size; i++)
            buffer[i + 1] = pchar[i];

        return size + 1;
    }

    size_t handle_get_tickets()
    {
        // reservation_id, cookie
        reservation_id_t reservation_id = *(reservation_id_t *)(buffer + 1);
        std::vector<char> cookie(buffer + 1 + sizeof(reservation_id), buffer + 1 + sizeof(reservation_id) + COOKIE_SIZE);
    }

    size_t handle_request()
    {
        request_type_t request_type{(message_id_t)buffer[0]};
        size_t response_len = 0;

        switch (request_type)
        {
        case request_type_t::GET_EVENTS:
            response_len = handle_get_events();
            break;
        case request_type_t::GET_RESERVATION:
            response_len = handle_get_reservation();
            break;
        case request_type_t::GET_TICKETS:
            response_len = handle_get_tickets();
            break;
        default:
            if (DEBUG)
                std::cerr << "Incorrect message_id: " << (message_id_t)buffer[0] << " no response sent \n";
        }

        return response_len;
    }

public:
    TicketServer(std::string file_path, uint16_t port, uint64_t timeout)
        : ticket_menager(file_path), port(port), timeout(timeout)
    {
        memset(buffer, 0, sizeof(buffer));
        // socket binding
        socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd <= 0)
        {
            std::cerr << "errno code:  " << strerror(errno) << " " << errno;
            throw std::runtime_error("Unable to start server on specified port!");
        }

        struct sockaddr_in server_address;
        server_address.sin_family = AF_INET;                // IPv4
        server_address.sin_addr.s_addr = htonl(INADDR_ANY); // listening on all interfaces
        server_address.sin_port = htons(port);

        if (bind(socket_fd, (struct sockaddr *)&server_address,
                 (socklen_t)sizeof(server_address)) != 0)
        {
            std::cerr << "errno code:  " << strerror(errno) << " " << errno;
            throw std::runtime_error("Unable to start server on specified port!");
        }

        if (DEBUG)
        {
            std::cerr << "Succeeded to start server on port: " << port << "\n";
        }
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
                fprintf(stderr, "received %zd bytes from client %s:%u message: ", read_length, client_ip, client_port);
                for (size_t i = 0; i < read_length && i < DEBUG_MAX_MESSAGE_PRINT_LEN; i++)
                    printf("%02X ", buffer[i]);
                std::cerr << "\n";
            }

            size_t response_len = handle_request();
            if (response_len == 0)
                continue;

            send_message(&client_address, response_len);
        }
    }
};

int main(const int argc, const char *argv[])
{

    std::string file_path;
    uint16_t port;
    uint64_t timeout;

    std::tie(file_path, port, timeout) = pase_arguments(argc, argv);

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
            std::cerr << s << " ";
        std::cerr << "\n";
    }

    if (args.size() != 2 && args.size() != 4 && args.size() != 6)
        throw std::invalid_argument("invalid program's arguments number!");

    std::string file_path;
    uint16_t port = DEFAULT_SERVER_PORT;
    expiration_time_t timeout = DEFAULT_TIMEOUT;

    // process file path argument
    auto it = std::find(args.begin(), args.end(), "-f");
    if (it == args.end() || std::next(it, 1) == args.end())
        throw std::invalid_argument("you must specify events file path!");
    else
    {
        matched_arguments.insert(*it);
        it++;
        try
        {
            std::ifstream file;
            file.open(*it);
            file.close();
            file_path = *it;
        }
        catch (const std::exception &e)
        {
            std::cerr << __LINE__ << " " << e.what() << '\n';
            std::stringstream message;
            message << "incorrect file path or invalid file!"
                    << " " << *it;
            throw std::invalid_argument(message.str());
        }
        matched_arguments.insert(*it);
    }

    // process port number argument
    it = std::find(args.begin(), args.end(), "-p");
    if (it != args.end() && std::next(it, 1) == args.end())
        throw std::invalid_argument("incorrect port number!");
    else if (it != args.end())
    {
        matched_arguments.insert(*it);
        it++;
        try
        {
            std::stringstream maybe_port(*it);
            maybe_port >> port;
        }
        catch (const std::exception &e)
        {
            std::cerr << __LINE__ << " " << e.what() << '\n';
            std::stringstream message;
            message << "invalid port number!"
                    << " " << *it;
            throw std::invalid_argument(message.str());
        }
        matched_arguments.insert(*it);
    }

    // process timeout argument
    it = std::find(args.begin(), args.end(), "-t");
    if (it != args.end() && std::next(it, 1) == args.end())
        throw std::invalid_argument("incorrect timeout value!");
    else if (it != args.end())
    {
        matched_arguments.insert(*it);
        it++;
        try
        {
            std::stringstream maybe_timeout(*it);
            maybe_timeout >> timeout;
            if (timeout < 1 || timeout > 86400)
                throw std::invalid_argument("incorrect timeout range!");
        }
        catch (const std::exception &e)
        {
            std::cerr << __LINE__ << " " << e.what() << '\n';
            std::stringstream message;
            message << "invalid timeout value!"
                    << " " << *it;
            throw std::invalid_argument(message.str());
        }
        matched_arguments.insert(*it);
    }

    if (!std::all_of(
            args.begin(),
            args.end(),
            [&](auto argument)
            { return matched_arguments.find(argument) != matched_arguments.end(); }))
        throw std::invalid_argument("invalid arguments!");

    return {file_path, port, timeout};
}