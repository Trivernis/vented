use crate::client::VentedClient;
use crate::event::Event;
use crate::result::VentedResult;
use std::io::Write;
use std::net::TcpStream;

pub struct VentedTcpClient {
    connection: TcpStream,
}

impl VentedClient for VentedTcpClient {
    fn connect(address: &str) -> VentedResult<Self> {
        Ok(Self {
            connection: TcpStream::connect(address)?,
        })
    }

    fn emit(&mut self, mut event: Event) -> VentedResult<Event> {
        self.connection.write(&event.as_bytes())?;

        Event::from_bytes(&mut self.connection)
    }
}
