#include <iostream>
#include <string>
#include <sstream>
#include <chrono>
#include <vector>
#include <exception>
#include <algorithm>
#include <set>
#include <fstream>
#include <tuple>

#include <sys/types.h>
#include <sys/socket.h>

const bool DEBUG = true;

const uint16_t DEFAULT_SERVER_PORT = 2022;
const uint64_t DEFAULT_TIMEOUT = 5;

std::tuple<std::string, uint16_t, uint64_t> pase_arguments(const int argc, const char *argv[])
;

int main(const int argc, const char *argv[])
{
    std::string file_path;
    uint16_t port;
    uint64_t timeout;
    std::tie(file_path, port, timeout) = pase_arguments(argc, argv);
}

std::tuple<std::string, uint16_t, uint64_t> pase_arguments(const int argc, const char *argv[])
{
    std::vector<std::string> args;
    for(int i = 1; i < argc; i++)
        args.push_back(argv[i]);
    std::set<std::string> matched_arguments;

    if (DEBUG)
    {
        for (auto &s : args)
            std::cerr << s << " ";
    }

    if (args.size() != 2 && args.size() != 4 && args.size() != 6)
        throw std::invalid_argument("invalid program's arguments number!");

    std::string file_path;
    uint16_t port = DEFAULT_SERVER_PORT;
    uint64_t timeout = DEFAULT_TIMEOUT;

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
