//! Deal with NAT traversal using Nintendo service.

use socks::{Socks5Datagram, TargetAddr};
use std::convert::TryFrom;
use std::fmt::{self, Display};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

/// Looks up the IPv4 address for a given hostname via DNS.
pub fn lookup_host_v4(host: &str) -> io::Result<Ipv4Addr> {
    dns_lookup::lookup_host(host)?
        .into_iter()
        .map(|addr| match addr {
            IpAddr::V4(ip) => Some(ip),
            _ => None,
        })
        .filter(|addr| addr.is_some())
        .map(|addr| addr.unwrap())
        .next()
        .ok_or(io::Error::from(io::ErrorKind::NotFound))
}

/// Represents an socket which can send data to and receive data from a certain address.
pub trait RW: Send + Sync {
    /// Returns the socket address that this socket was created from.
    fn local_addr(&self) -> io::Result<SocketAddrV4>;

    /// Sends data on the socket to the given address.
    fn send_to(&self, buf: &[u8], addr: SocketAddrV4) -> io::Result<usize>;

    /// Receives a single datagram message on the socket.
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV4)>;

    /// Sets the read timeout to the timeout specified.
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()>;

    /// Sets the write timeout to the timeout specified.
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()>;

    /// Returns the read timeout of this socket.
    fn read_timeout(&self) -> io::Result<Option<Duration>>;

    /// Returns the write timeout of this socket.
    fn write_timeout(&self) -> io::Result<Option<Duration>>;
}

/// Represents an UDP datagram, containing a TCP stream keeping the SOCKS proxy alive and an UDP
/// socket sending and receiving data.
#[derive(Debug)]
pub struct Datagram {
    datagram: Socks5Datagram,
}

impl Datagram {
    /// Creates a new `Datagram`.
    pub fn bind(
        proxy: SocketAddrV4,
        addr: SocketAddrV4,
        auth: Option<(String, String)>,
    ) -> io::Result<Datagram> {
        let datagram = match auth {
            Some((username, password)) => Socks5Datagram::bind_with_password(
                proxy,
                addr,
                username.as_str(),
                password.as_str(),
            )?,
            None => Socks5Datagram::bind(proxy, addr)?,
        };

        Ok(Datagram { datagram })
    }
}

impl RW for Datagram {
    fn local_addr(&self) -> io::Result<SocketAddrV4> {
        let addr = self.datagram.get_ref().local_addr()?;

        match addr {
            SocketAddr::V4(addr) => Ok(addr),
            _ => unreachable!(),
        }
    }

    fn send_to(&self, buf: &[u8], addr: SocketAddrV4) -> io::Result<usize> {
        let size = self.datagram.send_to(buf, addr)?;

        Ok(size)
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        let (size, addr) = self.datagram.recv_from(buf)?;

        return match addr {
            TargetAddr::Ip(addr) => match addr {
                SocketAddr::V4(addr) => Ok((size, addr)),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.datagram.get_ref().set_read_timeout(dur)?;

        Ok(())
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.datagram.get_ref().set_write_timeout(dur)?;

        Ok(())
    }

    fn read_timeout(&self) -> io::Result<Option<Duration>> {
        let duration = self.datagram.get_ref().read_timeout()?;

        Ok(duration)
    }

    fn write_timeout(&self) -> io::Result<Option<Duration>> {
        let duration = self.datagram.get_ref().write_timeout()?;

        Ok(duration)
    }
}

/// Represents an UDP socket.
#[derive(Debug)]
pub struct Socket {
    socket: UdpSocket,
}

impl Socket {
    /// Creates a new `Socket`.
    pub fn bind(addr: SocketAddrV4) -> io::Result<Socket> {
        let socket = UdpSocket::bind(addr)?;

        Ok(Socket { socket })
    }
}

impl RW for Socket {
    fn local_addr(&self) -> io::Result<SocketAddrV4> {
        let addr = self.socket.local_addr()?;

        match addr {
            SocketAddr::V4(addr) => Ok(addr),
            _ => unreachable!(),
        }
    }

    fn send_to(&self, buf: &[u8], addr: SocketAddrV4) -> io::Result<usize> {
        let size = self.socket.send_to(buf, addr)?;

        Ok(size)
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        let (size, addr) = self.socket.recv_from(buf)?;

        match addr {
            SocketAddr::V4(addr) => Ok((size, addr)),
            _ => unreachable!(),
        }
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(dur)?;

        Ok(())
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.socket.set_write_timeout(dur)?;

        Ok(())
    }

    fn read_timeout(&self) -> io::Result<Option<Duration>> {
        let duration = self.socket.read_timeout()?;

        Ok(duration)
    }

    fn write_timeout(&self) -> io::Result<Option<Duration>> {
        let duration = self.socket.write_timeout()?;

        Ok(duration)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// Enumeration of NAT types.
pub enum NatType {
    /// Represents the NAT Type A.
    A,
    /// Represents the NAT Type B.
    B,
    /// Represents the NAT Type C.
    C,
    /// Represents the NAT Type D.
    D,
    /// Represents the NAT Type F.
    F,
}

impl NatType {
    /// Returns the Nintendo (Nintendo Switch) NAT type.
    pub fn nintendo(&self) -> String {
        self.to_string()
    }

    /// Returns the Sony (PlayStation) NAT type.
    pub fn sony(&self) -> String {
        match self {
            NatType::A => "1".to_string(),
            NatType::B => "2".to_string(),
            NatType::C => "3".to_string(),
            NatType::D => "3".to_string(),
            NatType::F => "-".to_string(),
        }
    }

    /// Returns the Microsoft (Xbox) NAT type.
    pub fn microsoft(&self) -> String {
        match self {
            NatType::A => "Open".to_string(),
            NatType::B => "Moderate".to_string(),
            NatType::C => "Strict".to_string(),
            NatType::D => "Strict".to_string(),
            NatType::F => "Unavailable".to_string(),
        }
    }
}

impl Display for NatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NatType::A => write!(f, "A"),
            NatType::B => write!(f, "B"),
            NatType::C => write!(f, "C"),
            NatType::D => write!(f, "D"),
            NatType::F => write!(f, "F"),
        }
    }
}

/// Represents the payload for sending only.
const PAYLOAD_1: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// Represents the payload for an echoing back.
const PAYLOAD_2: [u8; 16] = [0, 0, 0, 0x65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// Represents the payload for receiving from another port.
const PAYLOAD_3: [u8; 16] = [0, 0, 0, 0x66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// Represents the payload for an echoing back.
const PAYLOAD_4: [u8; 16] = [0, 0, 0, 0x67, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

#[allow(dead_code)]
#[derive(Clone, Debug)]
/// Represents the response from the server.
struct Response {
    payload: [u8; 4],
    reserved: [u8; 2],
    port: u16,
    remote_ip: Ipv4Addr,
    local_ip: Ipv4Addr,
}

impl Response {
    fn unique_number(&self) -> u8 {
        self.payload[3]
    }

    /// Returns if the response is replied to a payload 2.
    fn is_payload_2(&self) -> bool {
        self.payload[3] == 0x65
    }

    /// Returns if the response is replied to a payload 3.
    fn is_payload_3(&self) -> bool {
        self.payload[3] == 0x66
    }

    /// Returns if the response is replied to a payload 4.
    fn is_payload_4(&self) -> bool {
        self.payload[3] == 0x67
    }

    #[allow(dead_code)]
    /// Returns the remote port from the server.
    fn port(&self) -> u16 {
        self.port
    }

    #[allow(dead_code)]
    /// Returns the remote IP address from the server.
    fn remote_ip(&self) -> Ipv4Addr {
        self.remote_ip
    }

    #[allow(dead_code)]
    /// Returns the local IP address from the server.
    fn local_ip(&self) -> Ipv4Addr {
        self.local_ip
    }

    /// Returns the remote address from the server.
    fn remote_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.remote_ip, self.port)
    }
}

impl From<[u8; 16]> for Response {
    fn from(s: [u8; 16]) -> Self {
        let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] = s;
        Response {
            payload: [a, b, c, d],
            reserved: [e, f],
            port: u16::from_be_bytes([g, h]),
            remote_ip: Ipv4Addr::new(i, j, k, l),
            local_ip: Ipv4Addr::new(m, n, o, p),
        }
    }
}

impl TryFrom<&[u8]> for Response {
    type Error = io::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value.len() {
            16 => {
                let mut s = [0u8; 16];
                s.clone_from_slice(&value);

                Ok(Response::from(s))
            }
            _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
        }
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.unique_number(), self.remote_addr())
    }
}

/// Represents the port for sending to only.
const PORT_1: u16 = 33334;
/// Represents the port for sending to and receiving from.
const PORT_2: u16 = 10025;
/// Represents the port for receiving from only.
const PORT_3: u16 = 50920;

/// Represents the times of sending packets at once.
const ONE_TIME_SEND: usize = 5;

/// Performs a test.
pub fn test(
    rw: &Box<dyn RW>,
    server1: Ipv4Addr,
    server2: Ipv4Addr,
) -> io::Result<(SocketAddrV4, SocketAddrV4, bool)> {
    // Server1:Port1, sending only
    let addr_1_1 = SocketAddrV4::new(server1, PORT_1);
    // Server1:Port2, echoing back or requesting receiving from another port
    let addr_1_2 = SocketAddrV4::new(server1, PORT_2);
    // Server1:Port3, receiving only
    let addr_1_3 = SocketAddrV4::new(server1, PORT_3);
    // Server2:Port2, echoing back
    let addr_2 = SocketAddrV4::new(server2, PORT_2);

    // Sending only
    for _ in 0..ONE_TIME_SEND {
        rw.send_to(&PAYLOAD_1, addr_1_1)?;
    }
    // Echoing back
    for _ in 0..ONE_TIME_SEND {
        rw.send_to(&PAYLOAD_2, addr_1_2)?;
    }
    // Receiving from another port
    for _ in 0..ONE_TIME_SEND {
        rw.send_to(&PAYLOAD_3, addr_1_2)?;
    }
    // Echoing back
    for _ in 0..ONE_TIME_SEND {
        rw.send_to(&PAYLOAD_4, addr_2)?;
    }

    let mut remote1 = None;
    let mut remote2 = None;
    let mut is_a = false;

    let mut buffer = vec![0u8; u16::MAX as usize];
    loop {
        match rw.recv_from(buffer.as_mut_slice()) {
            Ok((size, addr)) => {
                if size == 16 {
                    if addr == addr_1_2 {
                        let resp = Response::try_from(&buffer[..16]).unwrap();
                        if resp.is_payload_2() {
                            remote1 = Some(resp.remote_addr());
                        }
                    } else if addr == addr_1_3 {
                        let resp = Response::try_from(&buffer[..16]).unwrap();
                        if resp.is_payload_3() {
                            is_a = true;
                        }
                    } else if addr == addr_2 {
                        let resp = Response::try_from(&buffer[..16]).unwrap();
                        if resp.is_payload_4() {
                            remote2 = Some(resp.remote_addr());
                        }
                    }

                    if remote1.is_some() && remote2.is_some() && is_a {
                        break;
                    }
                }
            }
            Err(e) => {
                if remote1.is_some() && remote2.is_some() {
                    break;
                }
                return Err(e);
            }
        }
    }

    Ok((remote1.unwrap(), remote2.unwrap(), is_a))
}

/// Performs a NAT test.
pub fn nat_test(
    rw1: &Box<dyn RW>,
    rw2: &Box<dyn RW>,
    server1: Ipv4Addr,
    server2: Ipv4Addr,
) -> io::Result<(Option<Ipv4Addr>, NatType)> {
    let (remote1, remote2, is_a) = match test(rw1, server1, server2) {
        Ok((remote1, remote2, is_a)) => (remote1, remote2, is_a),
        Err(e) => match e.kind() {
            io::ErrorKind::TimedOut => return Ok((None, NatType::F)),
            _ => return Err(e),
        },
    };

    let ip = remote1.ip().clone();

    let port_a1 = remote1.port();
    let port_b1 = remote2.port();
    let nat = match port_a1 == port_b1 {
        true => match is_a {
            true => NatType::A,
            false => NatType::B,
        },
        false => {
            let (remote1, remote2) = match test(rw2, server1, server2) {
                Ok((remote1, remote2, _)) => (remote1, remote2),
                Err(e) => match e.kind() {
                    io::ErrorKind::TimedOut => return Ok((None, NatType::F)),
                    _ => return Err(e),
                },
            };
            let port_a2 = remote1.port();
            let port_b2 = remote2.port();
            match port_a2
                .checked_sub(port_a1)
                .unwrap_or_else(|| u16::MAX - (port_a1 - port_a2))
                == port_b2
                    .checked_sub(port_b1)
                    .unwrap_or_else(|| u16::MAX - (port_b1 - port_b2))
            {
                true => NatType::C,
                false => NatType::D,
            }
        }
    };

    Ok((Some(ip), nat))
}
