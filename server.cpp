#include "server.hpp"
#include "session.hpp"
#include <iostream>

Server::Server(boost::asio::io_service &io_service, short port,
               unsigned buffer_size)
    : acceptor(io_service, tcp::endpoint(tcp::v4(), port)),
      in_socket(io_service), buffer_size(buffer_size), session_id(0) {
  do_accept();
}

void Server::do_accept() {
  acceptor.async_accept(in_socket, [this](boost::system::error_code ec) {
    if (!ec) {
      std::make_shared<Session>(std::move(in_socket), session_id++, buffer_size)
          ->start();
    } else {
      std::cout << "socket accept error" << std::endl;
    }

    do_accept();
  });
}
