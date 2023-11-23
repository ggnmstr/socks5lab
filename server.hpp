#pragma once
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

class Server {

public:
  Server(boost::asio::io_service &io_service, short port, unsigned buffer_size);

private:
  void do_accept();

  tcp::acceptor acceptor;
  tcp::socket in_socket;
  size_t buffer_size;
  unsigned session_id;
};
