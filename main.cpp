#include "server.hpp"
#include <iostream>
#include <string>

int main(int argc, char **argv) {
  try {
    if (argc != 2) {
      std::cout << "Usage: ./proxy.out <port>" << std::endl;
      return 0;
    }

    int port = std::stoi(argv[1]);
    std::size_t buffer_size = 8192;

    boost::asio::io_context io_context;
    Server server(io_context, port, buffer_size);
    io_context.run();
  } catch (std::exception &e) {
    std::cout << "Exception: " << e.what() << std::endl;
  }
  return 0;
}
