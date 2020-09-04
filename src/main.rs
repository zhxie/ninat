use ninat::{Datagram, Socket, RW};
use std::clone::Clone;
use std::fmt::Display;
use std::io;
use std::net::{AddrParseError, SocketAddrV4};
use std::str::FromStr;
use std::time::Duration;
use structopt::StructOpt;

#[derive(Debug)]
enum ResolvableAddrParseError {
    AddrParseError(AddrParseError),
    ResolveError(io::Error),
}

impl Display for ResolvableAddrParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolvableAddrParseError::AddrParseError(e) => write!(f, "{}", e),
            ResolvableAddrParseError::ResolveError(e) => write!(f, "{}", e),
        }
    }
}

impl From<AddrParseError> for ResolvableAddrParseError {
    fn from(s: AddrParseError) -> Self {
        ResolvableAddrParseError::AddrParseError(s)
    }
}

impl From<io::Error> for ResolvableAddrParseError {
    fn from(s: io::Error) -> Self {
        ResolvableAddrParseError::ResolveError(s)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ResolvableSocketAddr {
    addr: SocketAddrV4,
    alias: Option<String>,
}

impl ResolvableSocketAddr {
    fn addr(&self) -> SocketAddrV4 {
        self.addr
    }
}

impl Display for ResolvableSocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.alias {
            Some(alias) => write!(f, "{} ({})", self.addr, alias),
            None => write!(f, "{}", self.addr),
        }
    }
}

impl FromStr for ResolvableSocketAddr {
    type Err = ResolvableAddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let has_alias;
        let addr = match s.parse() {
            Ok(addr) => {
                has_alias = false;

                addr
            }
            Err(e) => {
                has_alias = true;

                let v = s.split(":").collect::<Vec<_>>();
                if v.len() != 2 {
                    return Err(ResolvableAddrParseError::from(e));
                }

                let port = match v[1].parse() {
                    Ok(port) => port,
                    Err(_) => return Err(ResolvableAddrParseError::from(e)),
                };

                let ip = ninat::lookup_host_v4(v[0])?;

                SocketAddrV4::new(ip, port)
            }
        };

        let alias = match has_alias {
            true => Some(String::from_str(s).unwrap()),
            false => None,
        };
        Ok(ResolvableSocketAddr { addr, alias })
    }
}

#[derive(StructOpt, Clone, Debug, Eq, Hash, PartialEq)]
#[structopt(about)]
struct Flags {
    #[structopt(
        long = "socks-proxy",
        short = "s",
        help = "SOCKS proxy",
        value_name = "ADDRESS",
        display_order(0)
    )]
    pub proxy: Option<ResolvableSocketAddr>,
    #[structopt(
        long,
        help = "Username",
        value_name = "VALUE",
        requires("password"),
        display_order(1)
    )]
    pub username: Option<String>,
    #[structopt(
        long,
        help = "Password",
        value_name = "VALUE",
        requires("username"),
        display_order(2)
    )]
    pub password: Option<String>,
    #[structopt(
        long,
        short = "w",
        help = "Timeout to wait for each response",
        value_name = "VALUE",
        default_value = "3000",
        display_order(3)
    )]
    pub timeout: u64,
}

const NINTENDO_SRV_1: &str = "nncs1-lp1.n.n.srv.nintendo.net";
const NINTENDO_SRV_2: &str = "nncs2-lp1.n.n.srv.nintendo.net";

fn main() {
    // Parse arguments
    let flags = Flags::from_args();

    // Server
    let server1 = match ninat::lookup_host_v4(NINTENDO_SRV_1) {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };
    let server2 = match ninat::lookup_host_v4(NINTENDO_SRV_2) {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };

    // Bind socket
    let local = "0.0.0.0:0".parse().unwrap();
    let rw1: Box<dyn RW> = match &flags.proxy {
        Some(proxy) => {
            let auth = match flags.username.clone() {
                Some(username) => Some((username, flags.password.clone().unwrap())),
                None => None,
            };
            match Datagram::bind(proxy.addr(), local, auth) {
                Ok(datagram) => Box::new(datagram),
                Err(ref e) => {
                    eprintln!("{}", e);
                    return;
                }
            }
        }
        None => match Socket::bind(local) {
            Ok(socket) => Box::new(socket),
            Err(ref e) => {
                eprintln!("{}", e);
                return;
            }
        },
    };
    if flags.timeout != 0 {
        if let Err(ref e) = rw1.set_read_timeout(Some(Duration::from_millis(flags.timeout))) {
            eprintln!("{}", e);
            return;
        }
    }

    let local = "0.0.0.0:0".parse().unwrap();
    let rw2: Box<dyn RW> = match &flags.proxy {
        Some(proxy) => {
            let auth = match flags.username.clone() {
                Some(username) => Some((username, flags.password.clone().unwrap())),
                None => None,
            };
            match Datagram::bind(proxy.addr(), local, auth) {
                Ok(datagram) => Box::new(datagram),
                Err(ref e) => {
                    eprintln!("{}", e);
                    return;
                }
            }
        }
        None => match Socket::bind(local) {
            Ok(socket) => Box::new(socket),
            Err(ref e) => {
                eprintln!("{}", e);
                return;
            }
        },
    };
    if flags.timeout != 0 {
        if let Err(ref e) = rw2.set_read_timeout(Some(Duration::from_millis(flags.timeout))) {
            eprintln!("{}", e);
            return;
        }
    }

    // NAT test
    match ninat::nat_test(&rw1, &rw2, server1, server2) {
        Ok((ip, nat)) => {
            if let Some(ip) = ip {
                println!("Remote Address: {}", ip);
            }
            println!("NAT Type:");
            println!("  Nintendo Switch : {}", nat.nintendo());
            println!("  Sony PlayStation: {}", nat.sony());
            println!("  Microsoft Xbox  : {}", nat.microsoft());
        }
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };
}
