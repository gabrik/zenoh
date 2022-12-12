//
// Copyright (c) 2022 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
use super::{
    AuthenticatedPeerLink, PeerAuthenticator, PeerAuthenticatorId, PeerAuthenticatorTrait,
};
use crate::unicast::establishment::Cookie;
use async_trait::async_trait;
use rand::{Rng, SeedableRng};
use std::convert::TryInto;
use std::default::Default;
use std::sync::{Arc, RwLock};
use zenoh_buffers::ZSliceBuffer;
use zenoh_buffers::{
    reader::{DidntRead, HasReader, Reader},
    writer::{DidntWrite, HasWriter, Writer},
    ZSlice,
};
use zenoh_codec::{RCodec, WCodec, Zenoh060};
use zenoh_config::Config;
use zenoh_core::{bail, zerror, zresult::ShmError, Result as ZResult};
use zenoh_crypto::PseudoRng;
use zenoh_protocol::core::{ZInt, ZenohId};

const PAUSE_VERSION: ZInt = 0;
const PAUSE_NAME: &str = "pause";

const S_FLAG: u8 = 0x80;
const R_FLAG: u8 = 0x40;
const P_FLAG: u8 = 0x20;

/*************************************/
/*             InitSyn               */
/*************************************/
///  7 6 5 4 3 2 1 0
/// +-+-+-+-+-+-+-+-+
/// |0 0 0|  ATTCH  |
/// +-+-+-+---------+
/// |S|R|P|X|X|X|X|X|
/// +-+-+-+---------+
/// ~    version    ~
/// +---------------+
/// ~    Schedule   ~ if S == 1 -- the sleep shedule for the attachment sender
/// +---------------+
///
/// - if R == 1 and Ack is needed when Resuming a session
/// - if P == 1 and Ack is needed when Pausing a session
struct InitSynProperty {
    flags: u8,
    version: ZInt,
    schedule: Schedule,
}

impl InitSynProperty {
    fn get_schedule(&self) -> Option<&Schedule> {
        if self.flags & S_FLAG == S_FLAG {
            return Some(&self.schedule);
        }
        return None;
    }

    fn resume_ack(&self) -> bool {
        self.flags & R_FLAG == R_FLAG
    }

    fn pause_ack(&self) -> bool {
        self.flags & P_FLAG == P_FLAG
    }
}

/// The schedule for the pause period used by a node.
/// It follows the crontab format.
/// Field    Description    Allowed Value
/// minutes      Minute field    0 to 59 (-1) = *
/// hours     Hour field      0 to 23 (-1) = *
/// dom      Day of Month    1-31 (0,0) = *
/// months      Month field     1-12 (0,0) = *
/// dow      Day Of Week     0-6 (-1,-1) = *
///
/// # Example
/// If a node is available the first 15 minutes
/// of every our on Monday and Wednesday its schedule will be
/// minutes hours    dom      months    dow
///    15    -1    (-1,-1)   (-1,-1)  (0,2)
#[derive(Clone)]
struct Schedule {
    minutes: i8,
    hours: i8,
    dom: (i8, i8),
    months: (i8, i8),
    dow: (i8, i8),
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            minutes: -1,
            hours: -1,
            dom: (-1, -1),
            months: (0, 0),
            dow: (-1, -1),
        }
    }
}

impl Schedule {
    fn new(minutes: i8, hours: i8, dom: (i8, i8), months: (i8, i8), dow: (i8, i8)) -> Self {
        Self {
            minutes,
            hours,
            dom,
            months,
            dow,
        }
    }
}

impl<W> WCodec<&Schedule, &mut W> for Zenoh060
where
    W: Writer,
{
    type Output = Result<(), DidntWrite>;

    fn write(self, writer: &mut W, x: &Schedule) -> Self::Output {
        self.write(&mut *writer, x.minutes)?;
        self.write(&mut *writer, x.hours)?;
        self.write(&mut *writer, x.dom.0)?;
        self.write(&mut *writer, x.dom.1)?;
        self.write(&mut *writer, x.months.0)?;
        self.write(&mut *writer, x.months.1)?;
        self.write(&mut *writer, x.dow.0)?;
        self.write(&mut *writer, x.dow.1)?;

        Ok(())
    }
}

impl<R> RCodec<Schedule, &mut R> for Zenoh060
where
    R: Reader,
{
    type Error = DidntRead;

    fn read(self, reader: &mut R) -> Result<Schedule, Self::Error> {
        let minutes: i8 = self.read(&mut *reader)?;
        let hours: i8 = self.read(&mut *reader)?;
        let dom0: i8 = self.read(&mut *reader)?;
        let dom1: i8 = self.read(&mut *reader)?;
        let months0: i8 = self.read(&mut *reader)?;
        let months1: i8 = self.read(&mut *reader)?;
        let dow0: i8 = self.read(&mut *reader)?;
        let dow1: i8 = self.read(&mut *reader)?;
        Ok(Schedule::new(
            minutes,
            hours,
            (dom0, dom1),
            (months0, months1),
            (dow0, dow1),
        ))
    }
}

impl<W> WCodec<&InitSynProperty, &mut W> for Zenoh060
where
    W: Writer,
{
    type Output = Result<(), DidntWrite>;

    fn write(self, writer: &mut W, x: &InitSynProperty) -> Self::Output {
        self.write(&mut *writer, x.flags)?;
        self.write(&mut *writer, x.version)?;

        if x.flags & S_FLAG == S_FLAG {
            self.write(&mut *writer, &x.schedule)?;
        }

        Ok(())
    }
}

impl<R> RCodec<InitSynProperty, &mut R> for Zenoh060
where
    R: Reader,
{
    type Error = DidntRead;

    fn read(self, reader: &mut R) -> Result<InitSynProperty, Self::Error> {
        let flags: u8 = self.read(&mut *reader)?;
        let version: ZInt = self.read(&mut *reader)?;
        let schedule = match flags & S_FLAG == S_FLAG {
            true => {
                let res = self.read(&mut *reader)?;
                res
            }
            _ => Schedule::default(),
        };

        Ok(InitSynProperty {
            flags,
            version,
            schedule,
        })
    }
}

/*************************************/
/*             InitSyn               */
/*************************************/
///  7 6 5 4 3 2 1 0
/// +-+-+-+-+-+-+-+-+
/// |0 0 0|  ATTCH  |
/// +-+-+-+---------+
/// |S|R|P|X|X|X|X|X|
/// +-+-+-+---------+
/// ~    version    ~
/// +---------------+
/// ~    Schedule   ~ if S == 1 -- the agreed schedule
/// +---------------+
///
/// - if R == 1 and Ack is needed when Resuming a session
/// - if P == 1 and Ack is needed when Pausing a session
///
struct InitAckProperty {
    flags: u8,
    version: ZInt,
    schedule: Schedule,
}

impl<W> WCodec<&InitAckProperty, &mut W> for Zenoh060
where
    W: Writer,
{
    type Output = Result<(), DidntWrite>;

    fn write(self, writer: &mut W, x: &InitAckProperty) -> Self::Output {
        self.write(&mut *writer, x.flags)?;
        self.write(&mut *writer, x.version)?;

        if x.flags & S_FLAG == S_FLAG {
            self.write(&mut *writer, x.schedule.minutes)?;
            self.write(&mut *writer, x.schedule.hours)?;
            self.write(&mut *writer, x.schedule.dom.0)?;
            self.write(&mut *writer, x.schedule.dom.1)?;
            self.write(&mut *writer, x.schedule.months.0)?;
            self.write(&mut *writer, x.schedule.months.1)?;
            self.write(&mut *writer, x.schedule.dow.0)?;
            self.write(&mut *writer, x.schedule.dow.1)?;
        }

        Ok(())
    }
}

impl<R> RCodec<InitAckProperty, &mut R> for Zenoh060
where
    R: Reader,
{
    type Error = DidntRead;

    fn read(self, reader: &mut R) -> Result<InitAckProperty, Self::Error> {
        let flags: u8 = self.read(&mut *reader)?;
        let version: ZInt = self.read(&mut *reader)?;
        let schedule = match flags & S_FLAG == S_FLAG {
            true => {
                let minutes: i8 = self.read(&mut *reader)?;
                let hours: i8 = self.read(&mut *reader)?;
                let dom0: i8 = self.read(&mut *reader)?;
                let dom1: i8 = self.read(&mut *reader)?;
                let months0: i8 = self.read(&mut *reader)?;
                let months1: i8 = self.read(&mut *reader)?;
                let dow0: i8 = self.read(&mut *reader)?;
                let dow1: i8 = self.read(&mut *reader)?;
                Schedule::new(
                    minutes,
                    hours,
                    (dom0, dom1),
                    (months0, months1),
                    (dow0, dow1),
                )
            }
            _ => Schedule::default(),
        };

        Ok(InitAckProperty {
            flags,
            version,
            schedule,
        })
    }
}

/*************************************/
/*          Authenticator            */
/*************************************/
pub struct PauseCapability {
    resume_ack: bool,
    pause_ack: bool,
    schedule: Option<Schedule>,
}

impl Default for PauseCapability {
    fn default() -> Self {
        Self {
            resume_ack: false,
            pause_ack: true,
            schedule: None,
        }
    }
}

impl PauseCapability {
    pub fn make() -> ZResult<Self> {
        Ok(Self::default())
    }

    pub async fn from_config(config: &Config) -> ZResult<Option<Self>> {
        // TBD
        // Need of Pause Ack
        // Need of Resume Ack
        // Eventual Schedule

        // if *config.transport().pause().enabled() {

        //     Ok(Some(Self::default()))
        // } else {
        //     Ok(None)
        // }

        Ok(Some(Self::default()))
    }

    fn get_flags(&self) -> u8 {
        let mut flags = 0x00;

        if self.resume_ack {
            flags = flags | R_FLAG;
        }
        if self.pause_ack {
            flags = flags | P_FLAG;
        }
        if self.schedule.is_some() {
            flags = flags | S_FLAG;
        }

        flags
    }
}

unsafe impl Send for PauseCapability {}
unsafe impl Sync for PauseCapability {}

#[async_trait]
impl PeerAuthenticatorTrait for PauseCapability {
    fn id(&self) -> PeerAuthenticatorId {
        PeerAuthenticatorId::Shm
    }

    async fn close(&self) {
        // No cleanup needed
    }

    async fn get_init_syn_properties(
        &self,
        link: &AuthenticatedPeerLink,
        _peer_id: &ZenohId,
    ) -> ZResult<Option<Vec<u8>>> {
        let init_syn_property = InitSynProperty {
            flags: self.get_flags(),
            version: PAUSE_VERSION,
            schedule: match &self.schedule {
                Some(s) => s.clone(),
                None => Schedule::default(),
            },
        };
        let mut buff = vec![];
        let codec = Zenoh060::default();

        let mut writer = buff.writer();
        codec
            .write(&mut writer, &init_syn_property)
            .map_err(|_| zerror!("Error in encoding InitSyn for Pause on link: {}", link))?;

        Ok(Some(buff))
    }

    async fn handle_init_syn(
        &self,
        link: &AuthenticatedPeerLink,
        cookie: &Cookie,
        mut property: Option<Vec<u8>>,
    ) -> ZResult<(Option<Vec<u8>>, Option<Vec<u8>>)> {
        let buffer = match property.take() {
            Some(p) => p,
            None => {
                log::debug!("Peer {} did not express interest in Pause", cookie.zid);
                return Ok((None, None));
            }
        };

        let codec = Zenoh060::default();
        let mut reader = buffer.reader();

        let mut init_syn_property: InitSynProperty = codec
            .read(&mut reader)
            .map_err(|_| zerror!("Received InitSyn with invalid attachment on link: {}", link))?;

        if init_syn_property.version > PAUSE_VERSION {
            bail!("Rejected InitSyn with invalid attachment on link: {}", link)
        }

        // Here we should merge the schedules
        // and update the flags
        log::debug!("Checking Pause configuration...");

        // Create the InitAck attachment
        let init_ack_property = InitAckProperty {
            flags: init_syn_property.flags,
            version: init_syn_property.version,
            schedule: init_syn_property.schedule,
        };

        // Encode the InitAck property
        let mut buffer = vec![];
        let mut writer = buffer.writer();
        codec
            .write(&mut writer, &init_ack_property)
            .map_err(|_| zerror!("Error in encoding InitSyn for Pause on link: {}", link))?;

        Ok((Some(buffer), None))
    }

    async fn handle_init_ack(
        &self,
        link: &AuthenticatedPeerLink,
        peer_id: &ZenohId,
        _sn_resolution: ZInt,
        mut property: Option<Vec<u8>>,
    ) -> ZResult<Option<Vec<u8>>> {
        let buffer = match property.take() {
            Some(p) => p,
            None => {
                log::debug!("Peer {} did not express interest in Pause", peer_id);
                return Ok(None);
            }
        };

        let codec = Zenoh060::default();
        let mut reader = buffer.reader();

        let mut init_ack_property: InitAckProperty = codec
            .read(&mut reader)
            .map_err(|_| zerror!("Received InitAck with invalid attachment on link: {}", link))?;

        // Here we should configure our side

        Ok(None)
    }

    async fn handle_open_syn(
        &self,
        link: &AuthenticatedPeerLink,
        _cookie: &Cookie,
        property: (Option<Vec<u8>>, Option<Vec<u8>>),
    ) -> ZResult<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn handle_open_ack(
        &self,
        _link: &AuthenticatedPeerLink,
        _property: Option<Vec<u8>>,
    ) -> ZResult<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn handle_link_err(&self, _link: &AuthenticatedPeerLink) {}

    async fn handle_close(&self, _peer_id: &ZenohId) {}
}

//noinspection ALL
impl From<Arc<PauseCapability>> for PeerAuthenticator {
    fn from(v: Arc<PauseCapability>) -> PeerAuthenticator {
        PeerAuthenticator(v)
    }
}

impl From<PauseCapability> for PeerAuthenticator {
    fn from(v: PauseCapability) -> PeerAuthenticator {
        Self::from(Arc::new(v))
    }
}
