use crate::Identity;
use futures::sink::SinkExt as _;
use keynesis::{passport::{Event, EventAction, EventId, PassportError}, PublicIdentity};
use tokio::{io, stream::StreamExt as _};
use tokio_util::codec::{FramedRead, FramedWrite};

pub struct Passport {
    passport: keynesis::Passport,
}

impl Passport {
    pub fn new(identity: &Identity) -> Self {
        Self {
            passport: keynesis::Passport::new(identity.private_key()),
        }
    }

    pub fn load_event(&mut self, event: Event) -> Result<(), PassportError> {
        self.passport.load_event(event)
    }

    pub fn events(&self) -> Vec<Event> {
        self.passport.iter().cloned().collect()
    }

    pub fn next_event_declare(&self, identity: &Identity, with: PublicIdentity) -> Event {
        let mut event = self.passport.prepare_next_event(
            EventAction::Declaration { with }
        );

        event.force_self_sign(identity.private_key());

        event
    }

    pub fn next_event_repudiate(&self, identity: &Identity, event: EventId) -> Event {
        let mut event = self.passport.prepare_next_event(
            EventAction::Repudiation { event }
        );

        event.force_self_sign(identity.private_key());

        event
    }

    pub async fn import<IN>(reader: &mut IN) -> io::Result<Self>
    where
        IN: io::AsyncRead + Unpin,
    {
        let mut reader = FramedRead::new(reader, keynesis::passport::EventCodec);

        let mut passport = if let Some(event) = reader.next().await {
            let event = event.map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            keynesis::Passport::new_with(event)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Expecting to read the first entry of a passport",
            ));
        };

        while let Some(event) = reader.next().await {
            let event = event.map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            passport
                .load_event(event)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        }

        Ok(Self { passport })
    }

    pub async fn export<OUT>(&self, writer: &mut OUT) -> io::Result<()>
    where
        OUT: io::AsyncWrite + Unpin,
    {
        let mut writer = FramedWrite::new(writer, keynesis::passport::EventCodec);

        for event in self.passport.iter() {
            writer.send(event).await.unwrap();
        }

        Ok(())
    }
}
