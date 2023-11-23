#pragma once
#include <boost/asio.hpp>
#include <memory>
#include <type_traits>

using boost::asio::ip::tcp;

class Session : public std::enable_shared_from_this<Session> {
public:
  Session(tcp::socket in_socket, unsigned session_id, size_t buffer_size);

  void start();

private:
  void read_socks5_handshake();
  void write_socks5_handshake();
  void read_socks5_request();
  void do_resolve();
  void do_connect(tcp::resolver::iterator &it);
  void write_socks5_response();
  void do_read(int direction);
  void do_write(int direction, std::size_t Length);

  tcp::socket in_socket;
  tcp::socket out_socket;
  tcp::resolver resolver;

  std::string remote_host;
  std::string remote_port;
  std::vector<char> in_buf;
  std::vector<char> out_buf;
  int session_id;
};
