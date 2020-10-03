mod identity;
mod passport;
mod random;

use self::{identity::Identity, passport::Passport, random::Seed};
use keynesis::{
    passport::{Event, EventId},
    PublicIdentity,
};
use std::path::PathBuf;
use structopt::StructOpt;
use tokio::{
    fs,
    io::{self, AsyncWrite},
};

/// Keynesis command line tool
///
/// Allow for all offline operation with the local identity and the passport
#[derive(Debug, StructOpt)]
#[structopt(about = "the Keynesis command Line toolkit")]
enum Kli {
    /// all that is identity related operation (new, info...)
    Identity(IdentityCommand),
    /// Manage the passport
    Passport(PassportCommand),
    /// Create new events
    Event(EventCommand),
}

#[derive(Debug, StructOpt)]
enum PassportCommand {
    /// create a new passport, if you already have one passport
    /// you should be looking to instead use this one.
    ///
    /// Passport can be safely shared as they don't embed any
    /// private cryptographic material
    New {
        /// set the path where stored the identity is.
        #[structopt(long, env = "KLI_IDENTITY")]
        identity: PathBuf,

        /// set the path to store the new passport
        ///
        /// if none is given, then the passport will be printed
        /// on the standard output.
        #[structopt(long, env = "KLI_PASSPORT")]
        passport: Option<PathBuf>,
    },
    /// print all the events defining the passport
    ///
    Info {
        /// set the path to where the passport is.
        #[structopt(long, env = "KLI_PASSPORT")]
        passport: Option<PathBuf>,

        /// display all the active public identities
        #[structopt(long)]
        active_ids: bool,

        /// display the all the events of the passport
        #[structopt(long)]
        events: bool,
    },
    /// add an event in the Passport
    ///
    /// This function will check that the event is actually compatible
    /// with the passport (it will check the proofs and that the author)
    /// is an authorized party
    Load {
        /// set the path to where the passport is.
        #[structopt(long, env = "KLI_PASSPORT")]
        passport: PathBuf,

        /// set the path where stored the Event is
        ///
        /// read from the standard input if nothing given
        event: Option<PathBuf>,
    },
}

#[derive(Debug, StructOpt)]
enum EventCommand {
    /// display the info of the event
    Info {
        /// set the path to the event to sign
        ///
        /// if nothing given, the event will be read from
        /// standard input
        #[structopt(long)]
        event: Option<PathBuf>,
    },
    /// Create a new declaration event
    ///
    /// This event type is useful for adding new `Identity`
    /// to a `Passport`. Linking a device or a recover paper
    /// to this `Passport` for control or other party to
    /// trust/encrypt message to.
    Declare {
        /// set the path where stored the identity is.
        #[structopt(long, env = "KLI_IDENTITY")]
        identity: PathBuf,

        /// set the path to where the passport is.
        #[structopt(long, env = "KLI_PASSPORT")]
        passport: PathBuf,

        /// set the path to store the new event in.
        #[structopt(long)]
        event: Option<PathBuf>,

        /// set the path where stored the identity public key to declare is.
        new_identity: PublicIdentity,
    },
    /// Create an repudiation event
    ///
    /// This repudiation event will take an event ID to repudiate
    /// this will make the changes of this event as invalid.
    /// If it was an event to declare a new `PublicIdentity` this
    /// public identity will be discarded.
    ///
    /// Though, nothing is permanently removed. The repudiated event
    /// will remain in the passport as it will be needed for future
    /// proofs or any other event that was authored with this identity
    Repudiate {
        /// set the path where stored the identity is.
        #[structopt(long, env = "KLI_IDENTITY")]
        identity: PathBuf,

        /// set the path to where the passport is.
        #[structopt(long, env = "KLI_PASSPORT")]
        passport: PathBuf,

        /// set the path to store the new event in.
        #[structopt(long)]
        event: Option<PathBuf>,

        /// the event id to repudiate
        event_id: EventId,
    },
    /// Add an extra signature to the given event
    ///
    /// If this is a declaration event, the added signature
    /// should be added to `--index 1`
    ExtraSignature {
        /// set the path where stored the identity is.
        #[structopt(long, env = "KLI_IDENTITY")]
        identity: PathBuf,

        /// set the signature index, this matter regarding to how the
        /// event proof will be verified later
        ///
        #[structopt(long, default_value = "1")]
        index: usize,

        /// set the path to the event to sign
        ///
        /// if nothing given, the event will be read from
        /// standard input and will be written in the
        /// standard output
        #[structopt(long)]
        event: Option<PathBuf>,
    },
}

#[derive(Debug, StructOpt)]
enum IdentityCommand {
    /// Generate a new identity
    ///
    /// This function allow to generate a new identity. This identity
    /// is then stored in the associated identity path. Do not share
    /// or lose this generated identity as it will be needed to
    /// control the passport and participate to the different protocols
    /// with other passports/identity
    Generate {
        /// it is possible to set a `Seed`, though it is not recommended
        /// as it is for debug only
        ///
        /// this parameter set a deterministic `Seed` to "seed" a
        /// pseudo random number generator. This allows being able
        /// to reproduce exactly some behavior.
        #[structopt(long, default_value)]
        seed: Seed,

        /// set the path to store the generate identity.
        ///
        /// if none is given, then the identity's secret will be printed
        /// on the standard output.
        #[structopt(env = "KLI_IDENTITY")]
        identity: Option<PathBuf>,
    },
    /// Display the public information of the given identity
    ///
    Info {
        /// set the path where stored the identity is.
        ///
        /// if none is given, then the identity's secret will be read
        /// from the standard output.
        #[structopt(long, env = "KLI_IDENTITY")]
        identity: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Kli::from_args();

    match cli {
        Kli::Identity(IdentityCommand::Info { identity }) => {
            let mut reader = input_or_standard_input(&identity).await.unwrap();
            let identity = Identity::import(&mut reader).await.unwrap();

            println!("{} (Public Identity)", identity.public_id());
            println!("{} (Verify Key)", identity.public_id().verify_key());
        }
        Kli::Identity(IdentityCommand::Generate { seed, identity }) => {
            let mut rng = seed.into_cha_cha_rng();
            let mut writer = output_or_standard_output(&identity).await.unwrap();

            let identity = Identity::generate_new(&mut rng);
            identity.export(&mut writer).await.unwrap();
        }
        Kli::Passport(PassportCommand::New { identity, passport }) => {
            let identity = {
                let mut reader = input_or_standard_input(&Some(identity)).await.unwrap();
                Identity::import(&mut reader).await.unwrap()
            };

            let new_passport = Passport::new(&identity);

            let mut writer = output_or_standard_output(&passport).await.unwrap();
            new_passport.export(&mut writer).await.unwrap();
        }
        Kli::Passport(PassportCommand::Info { passport, active_ids, events }) => {
            let passport = {
                let mut reader = input_or_standard_input(&passport).await.unwrap();
                Passport::import(&mut reader).await.unwrap()
            };

            if events {
                serde_json::to_writer_pretty(std::io::stdout(), &passport.events()).unwrap();
            }
        }
        Kli::Passport(PassportCommand::Load { passport, event }) => {
            let mut p = {
                let mut reader = input_or_standard_input(&Some(passport.clone()))
                    .await
                    .unwrap();
                Passport::import(&mut reader).await.unwrap()
            };
            let event: Event = if let Some(path) = event {
                let file = std::fs::File::open(path).unwrap();
                serde_json::from_reader(file).unwrap()
            } else {
                serde_json::from_reader(std::io::stdin()).unwrap()
            };

            p.load_event(event).unwrap();

            let mut writer = output_or_standard_output(&Some(passport)).await.unwrap();
            p.export(&mut writer).await.unwrap();
        }
        Kli::Event(EventCommand::Declare { identity, new_identity, passport , event: event_output}) => {
            let passport = {
                let mut reader = input_or_standard_input(&Some(passport)).await.unwrap();
                Passport::import(&mut reader).await.unwrap()
            };
            let identity = {
                let mut reader = input_or_standard_input(&Some(identity)).await.unwrap();
                Identity::import(&mut reader).await.unwrap()
            };

            let event = passport.next_event_declare(&identity, new_identity);

            if let Some(path) = event_output {
                let file = std::fs::File::create(path).unwrap();
                serde_json::to_writer(file, &event).unwrap();
            } else {
                serde_json::to_writer_pretty(std::io::stdout(), &event).unwrap();
            };
        }
        Kli::Event(EventCommand::Repudiate { identity, event_id, passport , event: event_output}) => {
            let passport = {
                let mut reader = input_or_standard_input(&Some(passport)).await.unwrap();
                Passport::import(&mut reader).await.unwrap()
            };
            let identity = {
                let mut reader = input_or_standard_input(&Some(identity)).await.unwrap();
                Identity::import(&mut reader).await.unwrap()
            };

            let event = passport.next_event_repudiate(&identity, event_id);

            if let Some(path) = event_output {
                let file = std::fs::File::create(path).unwrap();
                serde_json::to_writer(file, &event).unwrap();
            } else {
                serde_json::to_writer_pretty(std::io::stdout(), &event).unwrap();
            };
        }
        Kli::Event(EventCommand::ExtraSignature { identity, index, event: event_path}) => {
            let identity = {
                let mut reader = input_or_standard_input(&Some(identity)).await.unwrap();
                Identity::import(&mut reader).await.unwrap()
            };
            let mut event: Event = if let Some(path) = &event_path {
                let file = std::fs::File::open(path).unwrap();
                serde_json::from_reader(file).unwrap()
            } else {
                serde_json::from_reader(std::io::stdin()).unwrap()
            };

            event.force_signature(identity.private_key(), index);

            if let Some(path) = event_path {
                let file = std::fs::File::create(path).unwrap();
                serde_json::to_writer(file, &event).unwrap();
            } else {
                serde_json::to_writer_pretty(std::io::stdout(), &event).unwrap();
            };
        }
        Kli::Event(EventCommand::Info { event}) => {
            let event: Event = if let Some(path) = event {
                let file = std::fs::File::open(path).unwrap();
                serde_json::from_reader(file).unwrap()
            } else {
                serde_json::from_reader(std::io::stdin()).unwrap()
            };

            serde_json::to_writer_pretty(std::io::stdout(), &event).unwrap();
        }
    }
}

async fn output_or_standard_output<P>(path: &Option<P>) -> io::Result<Box<dyn AsyncWrite + Unpin>>
where
    P: AsRef<std::path::Path>,
{
    if let Some(path) = path {
        let fs = fs::File::create(path).await?;
        Ok(Box::new(fs))
    } else {
        Ok(Box::new(io::stdout()))
    }
}

async fn input_or_standard_input<P>(path: &Option<P>) -> io::Result<Box<dyn io::AsyncRead + Unpin>>
where
    P: AsRef<std::path::Path>,
{
    if let Some(path) = path {
        let fs = fs::File::open(path).await?;
        Ok(Box::new(fs))
    } else {
        Ok(Box::new(io::stdin()))
    }
}
