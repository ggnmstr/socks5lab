#include "session.hpp"
#include "socks.hpp"
#include <boost/asio/write.hpp>
#include <boost/system/detail/error_code.hpp>
#include <cstdint>
#include <iostream>

#define slog(msg) std::cout << msg << std::endl;

Session::Session(tcp::socket in_socket, unsigned session_id, size_t buffer_size)
    : in_socket(std::move(in_socket)), out_socket(in_socket.get_executor()),
      resolver(in_socket.get_executor()), in_buf(buffer_size),
      out_buf(buffer_size), session_id(session_id) {}

void Session::start() { read_socks5_handshake(); }

void Session::read_socks5_handshake() {
  auto self(shared_from_this());
  in_socket.async_receive(
      boost::asio::buffer(in_buf),
      [this, self](boost::system::error_code ec, std::size_t length) {
        if (ec) {
          slog("SOCKS5 handshake request error!");
          return;
        }
        if (in_buf[0] != SOCKS5_VERSION) {
          slog("Handshake read: incompitable socks version!");
          return;
        }
        uint8_t num_methods = in_buf[1];

        in_buf[1] = SOCKS5_NO_ACCEPTABLE_METHODS;
        for (int i = 0; i < num_methods; i++) {
          if (in_buf[2 + i] == SOCKS5_NO_AUTH_REQUIRED) {
            in_buf[1] = SOCKS5_NO_AUTH_REQUIRED;
          }
        }
        write_socks5_handshake();
      }

  );
}

void Session::write_socks5_handshake() {
  auto self(shared_from_this());
  boost::asio::async_write(
      in_socket, boost::asio::buffer(in_buf, 2),
      [this, self](boost::system::error_code ec, std::size_t length) {
        if (ec) {
          slog("Write socks5 handshake error");
          return;
        }
        if (in_buf[1] == SOCKS5_NO_ACCEPTABLE_METHODS) {
          slog("Only no auth supported, closing connection");
          return;
        }
        read_socks5_request();
      });
}

void Session::read_socks5_request() {
  auto self(shared_from_this());

  in_socket.async_receive(
      boost::asio::buffer(in_buf),
      [this, self](boost::system::error_code ec, std::size_t length) {
        if (ec) {
          slog("read_socks5_request error: " << ec.message());
          return;
        }
        if (in_buf[0] != SOCKS5_VERSION ||
            in_buf[1] != SOCKS5_ESTABLISH_TCP_IP_CONNECTION) {
          slog("Invalid request, closing");
          return;
        }
        uint8_t addr_type = in_buf[3];
        uint8_t host_length;
        switch (addr_type) {
        case SOCKS5_IPV4:
          // ipv4 addres
          if (length != 10) {
            slog("SOCKS5 request length is invalid. Closing session.");
            return;
          }
          remote_host =
              boost::asio::ip::address_v4(ntohl(*((uint32_t *)&in_buf[4])))
                  .to_string();
          remote_port = std::to_string(ntohs(*((uint16_t *)&in_buf[8])));
          break;
        case SOCKS5_DOMAIN_NAME:
          // domain name
          host_length = in_buf[4];
          if (length != (size_t)(5 + host_length + 2)) {
            slog("SOCKS5 request length is invalid. Closing session.");
            return;
          }
          remote_host = std::string(&in_buf[5], host_length);
          remote_port =
              std::to_string(ntohs(*((uint16_t *)&in_buf[5 + host_length])));
          break;
        default:
          slog("Unsupported address type in SOCKS5 request. Closing session.");
          break;
        }
        do_resolve();
      });
}

void Session::do_resolve() {
  auto self(shared_from_this());
  resolver.async_resolve(tcp::resolver::query({remote_host, remote_port}),
                         [this, self](const boost::system::error_code &ec,
                                      tcp::resolver::iterator it) {
                           if (!ec) {
                             do_connect(it);
                           } else {
                             slog("failed to resolve " << remote_host << ":"
                                                       << remote_port);
                           }
                         });
}

void Session::do_connect(tcp::resolver::iterator &it) {

  auto self(shared_from_this());
  out_socket.async_connect(
      *it, [this, self](const boost::system::error_code &ec) {
        if (!ec) {
          slog("connected to " << remote_host << ":" << remote_port);
          write_socks5_response();
        } else {
          slog("failed to connect " << remote_host << ":" << remote_port);
        }
      });
}

void Session::write_socks5_response() {
  auto self(shared_from_this());
  in_buf[0] = SOCKS5_VERSION;
  in_buf[1] = SOCKS5_ZERO_RESERVED;
  in_buf[2] = SOCKS5_ZERO_RESERVED;

  in_buf[3] = SOCKS5_IPV4;
  uint32_t realRemoteIP =
      out_socket.remote_endpoint().address().to_v4().to_ulong();
  uint16_t realRemoteport = htons(out_socket.remote_endpoint().port());

  std::memcpy(&in_buf[4], &realRemoteIP, 4);
  std::memcpy(&in_buf[8], &realRemoteport, 2);

  boost::asio::async_write(
      in_socket, boost::asio::buffer(in_buf, 10),
      [this, self](boost::system::error_code ec, std::size_t length) {
        if (!ec) {
          // both sockets
          do_read(3);
        } else
          slog("Write socks5 response error");
      });
}

void Session::do_read(int direction) {

  auto self(shared_from_this());
  if (direction & 0x1)
    in_socket.async_receive(
        boost::asio::buffer(in_buf),
        [this, self](boost::system::error_code ec, std::size_t length) {
          if (!ec) {
            do_write(1, length);
          } else // if (ec != boost::asio::error::eof)
          {
            slog("Client socket read error, closing session. ");
            // probably client closed socket
            in_socket.close();
            out_socket.close();
          }
        });

  if (direction & 0x2)
    out_socket.async_receive(
        boost::asio::buffer(out_buf),
        [this, self](boost::system::error_code ec, std::size_t length) {
          if (!ec) {
            do_write(2, length);
          } else // if (ec != boost::asio::error::eof)
          {
            slog("Client socket read error, closing session. ");
            // probably remote server closed socket
            in_socket.close();
            out_socket.close();
          }
        });
}

void Session::do_write(int direction, std::size_t length) {

  auto self(shared_from_this());

  if (direction == 1) {

    boost::asio::async_write(
        out_socket, boost::asio::buffer(in_buf, length),
        [this, self, direction](boost::system::error_code ec,
                                std::size_t length) {
          if (!ec)
            do_read(direction);
          else {
            slog("Client socket write error, closing session. ");
            // probably client closed socket
            in_socket.close();
            out_socket.close();
          }
        });
  } else if (direction == 2) {
    boost::asio::async_write(
        in_socket, boost::asio::buffer(out_buf, length),
        [this, self, direction](boost::system::error_code ec,
                                std::size_t length) {
          if (!ec)
            do_read(direction);
          else {
            slog("Remote socket write error, closing session. ");
            // probably remote server closed socket
            in_socket.close();
            out_socket.close();
          }
        });
  }
}
