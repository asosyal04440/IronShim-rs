use crate::crypto::Sha256;
use crate::{containment_decision, AerEvent, AerSeverity, ContainmentDecision, PciIsolationCaps};

use libc::{c_ulong, ioctl};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::string::String;
use std::time::{Duration, Instant};
use std::vec::Vec;

const PCI_CFG_SPACE_EXP_SIZE: u64 = 4096;
const PCI_EXT_CAP_START: u16 = 0x100;
const PCI_EXT_CAP_ID_ATS: u16 = 0x0f;
const PCI_EXT_CAP_ID_SRIOV: u16 = 0x10;
const PCI_EXT_CAP_ID_PRI: u16 = 0x13;
const PCI_EXT_CAP_ID_PASID: u16 = 0x1b;
const PCI_EXT_CAP_ID_DPC: u16 = 0x1d;
const PCI_EXT_CAP_ID_DOE: u16 = 0x2e;
const PCI_EXT_CAP_NEXT_SHIFT: u32 = 20;
const PCI_EXT_CAP_NEXT_MASK: u32 = 0xffc0_0000;
const PCI_EXT_CAP_ID_MASK: u32 = 0x0000_ffff;

const PCI_DOE_CTRL: u16 = 0x08;
const PCI_DOE_STATUS: u16 = 0x0c;
const PCI_DOE_WRITE: u16 = 0x10;
const PCI_DOE_READ: u16 = 0x14;
const PCI_DOE_CTRL_ABORT: u32 = 0x0000_0001;
const PCI_DOE_CTRL_GO: u32 = 0x8000_0000;
const PCI_DOE_STATUS_BUSY: u32 = 0x0000_0001;
const PCI_DOE_STATUS_ERROR: u32 = 0x0000_0004;
const PCI_DOE_STATUS_DATA_OBJECT_READY: u32 = 0x8000_0000;
const PCI_DOE_HEADER_TYPE_SHIFT: u32 = 16;
const PCI_DOE_HEADER_TYPE_MASK: u32 = 0x00ff_0000;
const PCI_DOE_HEADER_LENGTH_MASK: u32 = 0x0003_ffff;

const PCI_EXP_DPC_CTL: u16 = 0x06;
const PCI_EXP_DPC_STATUS: u16 = 0x08;
const PCI_EXP_DPC_SOURCE_ID: u16 = 0x0a;
const PCI_EXP_DPC_RP_PIO_STATUS: u16 = 0x0c;
const PCI_EXP_DPC_RP_PIO_HEADER_LOG: u16 = 0x20;

const DOE_VENDOR_PCI_SIG: u16 = 0x0001;
const DOE_OBJECT_TYPE_SPDM: u8 = 0x01;
const SPDM_VERSION_10: u8 = 0x10;
const SPDM_VERSION_12: u8 = 0x12;
const SPDM_GET_VERSION: u8 = 0x84;
const SPDM_GET_DIGESTS: u8 = 0x81;
const SPDM_GET_CERTIFICATE: u8 = 0x82;
const SPDM_CHALLENGE: u8 = 0x83;
const SPDM_VERSION: u8 = 0x04;
const SPDM_DIGESTS: u8 = 0x01;
const SPDM_CERTIFICATE: u8 = 0x02;
const SPDM_CHALLENGE_AUTH: u8 = 0x03;
const SPDM_GET_MEASUREMENTS: u8 = 0xE0;
const SPDM_GET_CAPABILITIES: u8 = 0xE1;
const SPDM_NEGOTIATE_ALGORITHMS: u8 = 0xE3;
const SPDM_KEY_EXCHANGE: u8 = 0xE4;
const SPDM_FINISH: u8 = 0xE5;
const SPDM_MEASUREMENTS: u8 = 0x60;
const SPDM_CAPABILITIES: u8 = 0x61;
const SPDM_ALGORITHMS: u8 = 0x63;
const SPDM_KEY_EXCHANGE_RSP: u8 = 0x64;
const SPDM_FINISH_RSP: u8 = 0x65;

const IOMMUFD_TYPE: u8 = b';';
const IOMMUFD_CMD_IOAS_ALLOC: u8 = 0x81;
const IOMMUFD_CMD_IOAS_MAP: u8 = 0x85;
const IOMMUFD_CMD_IOAS_UNMAP: u8 = 0x86;
const IOMMUFD_CMD_HWPT_ALLOC: u8 = 0x89;
const IOMMUFD_CMD_HWPT_INVALIDATE: u8 = 0x8d;

const VFIO_TYPE: u8 = b';';
const VFIO_BASE: u8 = 100;
const VFIO_DEVICE_BIND_IOMMUFD_NR: u8 = VFIO_BASE + 18;
const VFIO_DEVICE_ATTACH_IOMMUFD_PT_NR: u8 = VFIO_BASE + 19;
const VFIO_DEVICE_DETACH_IOMMUFD_PT_NR: u8 = VFIO_BASE + 20;
const VFIO_DEVICE_BIND_FLAG_TOKEN: u32 = 1 << 0;
const VFIO_DEVICE_ATTACH_PASID: u32 = 1 << 0;
const VFIO_DEVICE_DETACH_PASID: u32 = 1 << 0;

const IOMMU_IOAS_MAP_FIXED_IOVA: u32 = 1 << 0;
const IOMMU_IOAS_MAP_WRITEABLE: u32 = 1 << 1;
const IOMMU_IOAS_MAP_READABLE: u32 = 1 << 2;
const IOMMU_HWPT_ALLOC_PASID: u32 = 1 << 3;
const IOMMU_HWPT_DATA_NONE: u32 = 0;
const IOMMU_HWPT_DATA_VTD_S1: u32 = 1;
const IOMMU_HWPT_INVALIDATE_DATA_VTD_S1: u32 = 0;
const IOMMU_VTD_INV_FLAGS_LEAF: u32 = 1 << 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PciBdf {
    pub domain: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciBdf {
    pub fn parse(input: &str) -> io::Result<Self> {
        let mut pieces = input.trim().split(':');
        let domain = pieces
            .next()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "missing domain"))?;
        let bus = pieces
            .next()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "missing bus"))?;
        let devfn = pieces
            .next()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "missing devfn"))?;
        if pieces.next().is_some() {
            return Err(io::Error::new(ErrorKind::InvalidInput, "invalid bdf"));
        }
        let mut devfn_parts = devfn.split('.');
        let device = devfn_parts
            .next()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "missing device"))?;
        let function = devfn_parts
            .next()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "missing function"))?;
        if devfn_parts.next().is_some() {
            return Err(io::Error::new(ErrorKind::InvalidInput, "invalid function"));
        }
        Ok(Self {
            domain: u16::from_str_radix(domain, 16)
                .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "domain"))?,
            bus: u8::from_str_radix(bus, 16)
                .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "bus"))?,
            device: u8::from_str_radix(device, 16)
                .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "device"))?,
            function: function
                .parse::<u8>()
                .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "function"))?,
        })
    }

    pub fn sysfs_name(&self) -> String {
        std::format!(
            "{:04x}:{:02x}:{:02x}.{}",
            self.domain,
            self.bus,
            self.device,
            self.function
        )
    }
}

impl fmt::Display for PciBdf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04x}:{:02x}:{:02x}.{}",
            self.domain, self.bus, self.device, self.function
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciExtendedCapability {
    pub id: u16,
    pub offset: u16,
    pub next: u16,
}

pub struct SysfsPciDevice {
    root: PathBuf,
    bdf: PciBdf,
    config: File,
}

impl SysfsPciDevice {
    pub fn open(bdf: PciBdf) -> io::Result<Self> {
        Self::open_with_root(Path::new("/sys/bus/pci/devices"), bdf)
    }

    pub fn open_with_root(root: &Path, bdf: PciBdf) -> io::Result<Self> {
        let config_path = root.join(bdf.sysfs_name()).join("config");
        let config = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&config_path)?;
        Ok(Self {
            root: root.to_path_buf(),
            bdf,
            config,
        })
    }

    pub fn bdf(&self) -> PciBdf {
        self.bdf
    }

    pub fn device_dir(&self) -> PathBuf {
        self.root.join(self.bdf.sysfs_name())
    }

    pub fn reset(&self) -> io::Result<()> {
        fs::write(self.device_dir().join("reset"), b"1\n")
    }

    pub fn remove(&self) -> io::Result<()> {
        fs::write(self.device_dir().join("remove"), b"1\n")
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset + buf.len() as u64 > PCI_CFG_SPACE_EXP_SIZE {
            return Err(io::Error::new(ErrorKind::InvalidInput, "config offset"));
        }
        self.config.read_exact_at(buf, offset)?;
        Ok(())
    }

    fn write_all_at(&self, offset: u64, buf: &[u8]) -> io::Result<()> {
        if offset + buf.len() as u64 > PCI_CFG_SPACE_EXP_SIZE {
            return Err(io::Error::new(ErrorKind::InvalidInput, "config offset"));
        }
        let written = self.config.write_at(buf, offset)?;
        if written != buf.len() {
            return Err(io::Error::new(
                ErrorKind::WriteZero,
                "short pci config write",
            ));
        }
        Ok(())
    }

    pub fn read_config_u16(&self, offset: u16) -> io::Result<u16> {
        let mut buf = [0u8; 2];
        self.read_exact_at(offset as u64, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    pub fn read_config_u32(&self, offset: u16) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact_at(offset as u64, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    pub fn write_config_u32(&self, offset: u16, value: u32) -> io::Result<()> {
        self.write_all_at(offset as u64, &value.to_le_bytes())
    }

    pub fn scan_extended_capabilities(&self) -> io::Result<Vec<PciExtendedCapability>> {
        let mut out = Vec::new();
        let mut offset = PCI_EXT_CAP_START;
        let mut guard = 0usize;
        while offset >= PCI_EXT_CAP_START && (offset as u64) < PCI_CFG_SPACE_EXP_SIZE && guard < 96
        {
            let header = self.read_config_u32(offset)?;
            if header == 0 || header == 0xffff_ffff {
                break;
            }
            let id = (header & PCI_EXT_CAP_ID_MASK) as u16;
            let next = ((header & PCI_EXT_CAP_NEXT_MASK) >> PCI_EXT_CAP_NEXT_SHIFT) as u16;
            out.push(PciExtendedCapability { id, offset, next });
            if next == 0 || next == offset {
                break;
            }
            offset = next;
            guard += 1;
        }
        Ok(out)
    }

    pub fn find_extended_capability(&self, cap_id: u16) -> io::Result<Option<u16>> {
        for cap in self.scan_extended_capabilities()? {
            if cap.id == cap_id {
                return Ok(Some(cap.offset));
            }
        }
        Ok(None)
    }

    pub fn isolation_caps(&self) -> io::Result<PciIsolationCaps> {
        let caps = self.scan_extended_capabilities()?;
        let ats = caps.iter().any(|cap| cap.id == PCI_EXT_CAP_ID_ATS);
        let pri = caps.iter().any(|cap| cap.id == PCI_EXT_CAP_ID_PRI);
        let pasid = caps.iter().any(|cap| cap.id == PCI_EXT_CAP_ID_PASID);
        Ok(PciIsolationCaps {
            ats,
            pri,
            pasid,
            sva: ats && pri && pasid,
        })
    }

    pub fn sriov_cap_offset(&self) -> io::Result<Option<u16>> {
        self.find_extended_capability(PCI_EXT_CAP_ID_SRIOV)
    }

    pub fn doe_cap_offset(&self) -> io::Result<Option<u16>> {
        self.find_extended_capability(PCI_EXT_CAP_ID_DOE)
    }

    pub fn dpc_cap_offset(&self) -> io::Result<Option<u16>> {
        self.find_extended_capability(PCI_EXT_CAP_ID_DPC)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoeResponse {
    pub vendor_id: u16,
    pub object_type: u8,
    pub payload_dwords: Vec<u32>,
}

pub struct DoeMailbox<'a> {
    device: &'a SysfsPciDevice,
    offset: u16,
    timeout: Duration,
}

impl<'a> DoeMailbox<'a> {
    pub fn new(device: &'a SysfsPciDevice, offset: u16) -> Self {
        Self {
            device,
            offset,
            timeout: Duration::from_millis(250),
        }
    }

    pub fn new_auto(device: &'a SysfsPciDevice) -> io::Result<Option<Self>> {
        Ok(device
            .doe_cap_offset()?
            .map(|offset| Self::new(device, offset)))
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    fn reg(&self, base: u16) -> u16 {
        self.offset + base
    }

    fn wait_until<F>(&self, predicate: F) -> io::Result<()>
    where
        F: Fn(u32) -> bool,
    {
        let deadline = Instant::now() + self.timeout;
        loop {
            let status = self.device.read_config_u32(self.reg(PCI_DOE_STATUS))?;
            if predicate(status) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(ErrorKind::TimedOut, "doe timeout"));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    pub fn abort(&self) -> io::Result<()> {
        self.device
            .write_config_u32(self.reg(PCI_DOE_CTRL), PCI_DOE_CTRL_ABORT)
    }

    pub fn exchange(
        &self,
        vendor_id: u16,
        object_type: u8,
        payload_dwords: &[u32],
    ) -> io::Result<DoeResponse> {
        self.wait_until(|status| (status & PCI_DOE_STATUS_BUSY) == 0)?;
        let stale = self.device.read_config_u32(self.reg(PCI_DOE_STATUS))?;
        if (stale & PCI_DOE_STATUS_DATA_OBJECT_READY) != 0 {
            self.abort()?;
            self.wait_until(|status| (status & PCI_DOE_STATUS_BUSY) == 0)?;
        }

        let header1 = (vendor_id as u32) | ((object_type as u32) << PCI_DOE_HEADER_TYPE_SHIFT);
        let header2 = (payload_dwords.len() as u32 + 2) & PCI_DOE_HEADER_LENGTH_MASK;
        self.device
            .write_config_u32(self.reg(PCI_DOE_WRITE), header1)?;
        self.device
            .write_config_u32(self.reg(PCI_DOE_WRITE), header2)?;
        for word in payload_dwords {
            self.device
                .write_config_u32(self.reg(PCI_DOE_WRITE), *word)?;
        }
        self.device
            .write_config_u32(self.reg(PCI_DOE_CTRL), PCI_DOE_CTRL_GO)?;
        self.wait_until(|status| {
            (status & PCI_DOE_STATUS_DATA_OBJECT_READY) != 0 || (status & PCI_DOE_STATUS_ERROR) != 0
        })?;

        let status = self.device.read_config_u32(self.reg(PCI_DOE_STATUS))?;
        if (status & PCI_DOE_STATUS_ERROR) != 0 {
            self.abort()?;
            return Err(io::Error::new(ErrorKind::Other, "doe mailbox error"));
        }

        let rsp_header1 = self.device.read_config_u32(self.reg(PCI_DOE_READ))?;
        let rsp_header2 = self.device.read_config_u32(self.reg(PCI_DOE_READ))?;
        let rsp_len = (rsp_header2 & PCI_DOE_HEADER_LENGTH_MASK) as usize;
        if rsp_len < 2 {
            return Err(io::Error::new(ErrorKind::InvalidData, "short doe response"));
        }
        let mut rsp_payload = Vec::with_capacity(rsp_len.saturating_sub(2));
        for _ in 0..rsp_len.saturating_sub(2) {
            rsp_payload.push(self.device.read_config_u32(self.reg(PCI_DOE_READ))?);
        }
        Ok(DoeResponse {
            vendor_id: (rsp_header1 & 0xffff) as u16,
            object_type: ((rsp_header1 & PCI_DOE_HEADER_TYPE_MASK) >> PCI_DOE_HEADER_TYPE_SHIFT)
                as u8,
            payload_dwords: rsp_payload,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmFrame {
    pub version: u8,
    pub code: u8,
    pub param1: u8,
    pub param2: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmVersionSet {
    pub versions: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmCapabilities {
    pub ct_exponent: u8,
    pub flags: u32,
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmAlgorithmTable {
    pub alg_type: u8,
    pub fixed_algorithms: Vec<u8>,
    pub external_algorithms: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmNegotiateAlgorithmsRequest {
    pub measurement_specification: u8,
    pub other_params_support: u8,
    pub base_asym_algo: u32,
    pub base_hash_algo: u32,
    pub pqc_asym_algo: u32,
    pub mel_specification: u8,
    pub tables: Vec<SpdmAlgorithmTable>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmAlgorithms {
    pub measurement_specification_sel: u8,
    pub other_params_selection: u8,
    pub measurement_hash_algo: u32,
    pub base_asym_sel: u32,
    pub base_hash_sel: u32,
    pub pqc_asym_sel: u32,
    pub mel_specification_sel: u8,
    pub tables: Vec<SpdmAlgorithmTable>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmDigestSet {
    pub supported_slot_mask: u8,
    pub provisioned_slot_mask: u8,
    pub digests: Vec<Vec<u8>>,
    pub trailing_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmCertificateChain {
    pub slot_id: u8,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmChallengeAuth {
    pub slot_id: u8,
    pub slot_mask: u8,
    pub cert_chain_hash: Vec<u8>,
    pub nonce: [u8; 32],
    pub measurement_summary_hash: Vec<u8>,
    pub opaque_data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmMeasurementRecord {
    pub number_of_blocks: u8,
    pub slot_id: u8,
    pub content_changed: u8,
    pub measurement_record: Vec<u8>,
    pub signed_tail: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmKeyExchangeRequest {
    pub measurement_summary_hash_type: u8,
    pub slot_id: u8,
    pub req_session_id: u16,
    pub session_policy: u8,
    pub random_data: [u8; 32],
    pub exchange_data: Vec<u8>,
    pub opaque_data: Vec<u8>,
    pub responder_exchange_data_len: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmKeyExchangeResponse {
    pub heartbeat_period: u8,
    pub rsp_session_id: u16,
    pub mut_auth_requested: u8,
    pub req_slot_id_param: u8,
    pub random_data: [u8; 32],
    pub exchange_data: Vec<u8>,
    pub measurement_summary_hash: Vec<u8>,
    pub opaque_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub verify_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmFinishResponse {
    pub verify_data: Vec<u8>,
    pub opaque_data: Vec<u8>,
}

pub struct SpdmRequester<'a> {
    mailbox: DoeMailbox<'a>,
    transcript: Sha256,
    negotiated_version: Option<u8>,
    capabilities: Option<SpdmCapabilities>,
    algorithms: Option<SpdmAlgorithms>,
}

impl<'a> SpdmRequester<'a> {
    pub fn new(mailbox: DoeMailbox<'a>) -> Self {
        Self {
            mailbox,
            transcript: Sha256::new(),
            negotiated_version: None,
            capabilities: None,
            algorithms: None,
        }
    }

    pub fn new_cma_spdm(mailbox: DoeMailbox<'a>) -> Self {
        Self::new(mailbox)
    }

    pub fn transcript_hash(self) -> [u8; 32] {
        self.transcript.finalize()
    }

    pub fn negotiated_version(&self) -> Option<u8> {
        self.negotiated_version
    }

    pub fn capabilities(&self) -> Option<&SpdmCapabilities> {
        self.capabilities.as_ref()
    }

    pub fn algorithms(&self) -> Option<&SpdmAlgorithms> {
        self.algorithms.as_ref()
    }

    pub fn negotiated_hash_size(&self) -> Option<usize> {
        self.algorithms
            .as_ref()
            .map(|algorithms| hash_size_from_algo(algorithms.base_hash_sel))
    }

    pub fn negotiated_signature_size(&self) -> Option<usize> {
        self.algorithms
            .as_ref()
            .map(|algorithms| signature_size_from_asym(algorithms.base_asym_sel))
    }

    pub fn exchange_frame(&mut self, frame: &SpdmFrame) -> io::Result<SpdmFrame> {
        let request_bytes = encode_spdm_frame(frame);
        self.transcript.update(&request_bytes);
        let words = bytes_to_dwords(&request_bytes);
        let response = self
            .mailbox
            .exchange(DOE_VENDOR_PCI_SIG, DOE_OBJECT_TYPE_SPDM, &words)?;
        if response.vendor_id != DOE_VENDOR_PCI_SIG || response.object_type != DOE_OBJECT_TYPE_SPDM
        {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "unexpected doe protocol",
            ));
        }
        let response_bytes = dwords_to_bytes(&response.payload_dwords);
        self.transcript.update(&response_bytes);
        decode_spdm_frame(&response_bytes)
    }

    pub fn get_version(&mut self) -> io::Result<SpdmFrame> {
        let response = self.exchange_frame(&SpdmFrame {
            version: SPDM_VERSION_10,
            code: SPDM_GET_VERSION,
            param1: 0,
            param2: 0,
            payload: Vec::new(),
        })?;
        if response.code != SPDM_VERSION {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "unexpected spdm response",
            ));
        }
        if let Some(version_set) = parse_versions(&response)? {
            self.negotiated_version = version_set.versions.iter().copied().max();
        }
        Ok(response)
    }

    pub fn get_versions(&mut self) -> io::Result<SpdmVersionSet> {
        let response = self.get_version()?;
        parse_versions(&response)?.ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "versions"))
    }

    pub fn get_capabilities(
        &mut self,
        ct_exponent: u8,
        flags: u32,
        data_transfer_size: u32,
        max_spdm_msg_size: u32,
    ) -> io::Result<SpdmCapabilities> {
        let version = self.negotiated_version.unwrap_or(SPDM_VERSION_12);
        let mut payload = Vec::with_capacity(16);
        payload.extend_from_slice(&[0u8, ct_exponent]);
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&flags.to_le_bytes());
        payload.extend_from_slice(&data_transfer_size.to_le_bytes());
        payload.extend_from_slice(&max_spdm_msg_size.to_le_bytes());
        let response = self.exchange_frame(&SpdmFrame {
            version,
            code: SPDM_GET_CAPABILITIES,
            param1: 0,
            param2: 0,
            payload,
        })?;
        if response.code != SPDM_CAPABILITIES || response.payload.len() < 12 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "unexpected spdm capabilities",
            ));
        }
        let capabilities = SpdmCapabilities {
            ct_exponent: response.payload[1],
            flags: u32::from_le_bytes(response.payload[4..8].try_into().unwrap()),
            data_transfer_size: u32::from_le_bytes(response.payload[8..12].try_into().unwrap()),
            max_spdm_msg_size: if response.payload.len() >= 16 {
                u32::from_le_bytes(response.payload[12..16].try_into().unwrap())
            } else {
                0
            },
        };
        self.capabilities = Some(capabilities.clone());
        Ok(capabilities)
    }

    pub fn negotiate_algorithms(
        &mut self,
        request: &SpdmNegotiateAlgorithmsRequest,
    ) -> io::Result<SpdmAlgorithms> {
        let version = self.negotiated_version.unwrap_or(SPDM_VERSION_12);
        let mut tables = Vec::new();
        for table in &request.tables {
            tables.extend_from_slice(&encode_algorithm_table(table)?);
        }
        let total_length = 32u16
            .checked_add(tables.len() as u16)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "algorithms length"))?;
        let mut payload = Vec::with_capacity(28 + tables.len());
        payload.extend_from_slice(&total_length.to_le_bytes());
        payload.push(request.measurement_specification);
        payload.push(request.other_params_support);
        payload.extend_from_slice(&request.base_asym_algo.to_le_bytes());
        payload.extend_from_slice(&request.base_hash_algo.to_le_bytes());
        payload.extend_from_slice(&request.pqc_asym_algo.to_le_bytes());
        payload.extend_from_slice(&[0u8; 8]);
        payload.push(0);
        payload.push(0);
        payload.push(0);
        payload.push(request.mel_specification);
        payload.extend_from_slice(&tables);
        let response = self.exchange_frame(&SpdmFrame {
            version,
            code: SPDM_NEGOTIATE_ALGORITHMS,
            param1: request.tables.len() as u8,
            param2: 0,
            payload,
        })?;
        if response.code != SPDM_ALGORITHMS || response.payload.len() < 28 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "unexpected spdm algorithms",
            ));
        }
        let algorithms = SpdmAlgorithms {
            measurement_specification_sel: response.payload[2],
            other_params_selection: response.payload[3],
            measurement_hash_algo: u32::from_le_bytes(response.payload[4..8].try_into().unwrap()),
            base_asym_sel: u32::from_le_bytes(response.payload[8..12].try_into().unwrap()),
            base_hash_sel: u32::from_le_bytes(response.payload[12..16].try_into().unwrap()),
            pqc_asym_sel: u32::from_le_bytes(response.payload[16..20].try_into().unwrap()),
            mel_specification_sel: response.payload[27],
            tables: decode_algorithm_tables(response.param1, &response.payload[28..])?,
        };
        self.algorithms = Some(algorithms.clone());
        Ok(algorithms)
    }

    pub fn get_digests(&mut self) -> io::Result<SpdmDigestSet> {
        let version = self.negotiated_version.unwrap_or(SPDM_VERSION_12);
        let hash_size = self.negotiated_hash_size().ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidData, "hash algorithm not negotiated")
        })?;
        let response = self.exchange_frame(&SpdmFrame {
            version,
            code: SPDM_GET_DIGESTS,
            param1: 0,
            param2: 0,
            payload: Vec::new(),
        })?;
        if response.code != SPDM_DIGESTS {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "unexpected spdm digests",
            ));
        }
        let slot_count = response.param2.count_ones() as usize;
        let digest_bytes = slot_count
            .checked_mul(hash_size)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "digest size overflow"))?;
        if response.payload.len() < digest_bytes {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "short digest response",
            ));
        }
        let mut digests = Vec::with_capacity(slot_count);
        let mut cursor = 0usize;
        for _ in 0..slot_count {
            digests.push(response.payload[cursor..cursor + hash_size].to_vec());
            cursor += hash_size;
        }
        Ok(SpdmDigestSet {
            supported_slot_mask: response.param1,
            provisioned_slot_mask: response.param2,
            digests,
            trailing_bytes: response.payload[cursor..].to_vec(),
        })
    }

    pub fn get_certificate(
        &mut self,
        slot_id: u8,
        chunk_len: u16,
    ) -> io::Result<SpdmCertificateChain> {
        let version = self.negotiated_version.unwrap_or(SPDM_VERSION_12);
        let mut offset = 0u16;
        let mut certificate = Vec::new();
        loop {
            let response = self.exchange_frame(&SpdmFrame {
                version,
                code: SPDM_GET_CERTIFICATE,
                param1: slot_id & 0x0f,
                param2: 0,
                payload: [&offset.to_le_bytes()[..], &chunk_len.to_le_bytes()[..]].concat(),
            })?;
            if response.code != SPDM_CERTIFICATE || response.payload.len() < 4 {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "unexpected certificate response",
                ));
            }
            let portion = u16::from_le_bytes(response.payload[0..2].try_into().unwrap()) as usize;
            let remainder = u16::from_le_bytes(response.payload[2..4].try_into().unwrap());
            if response.payload.len() < 4 + portion {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "short certificate chunk",
                ));
            }
            certificate.extend_from_slice(&response.payload[4..4 + portion]);
            if remainder == 0 {
                break;
            }
            offset = offset
                .checked_add(portion as u16)
                .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "certificate offset"))?;
        }
        Ok(SpdmCertificateChain {
            slot_id,
            bytes: certificate,
        })
    }

    pub fn challenge(
        &mut self,
        slot_id: u8,
        measurement_summary_hash_type: u8,
        nonce: [u8; 32],
    ) -> io::Result<SpdmChallengeAuth> {
        let version = self.negotiated_version.unwrap_or(SPDM_VERSION_12);
        let hash_size = self.negotiated_hash_size().ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidData, "hash algorithm not negotiated")
        })?;
        let signature_size = self.negotiated_signature_size().ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidData, "signature algorithm not negotiated")
        })?;
        let response = self.exchange_frame(&SpdmFrame {
            version,
            code: SPDM_CHALLENGE,
            param1: slot_id & 0x0f,
            param2: measurement_summary_hash_type,
            payload: nonce.to_vec(),
        })?;
        if response.code != SPDM_CHALLENGE_AUTH
            || response.payload.len() < hash_size + 32 + hash_size + 2 + signature_size
        {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "unexpected challenge response",
            ));
        }
        let mut cursor = 0usize;
        let cert_chain_hash = response.payload[cursor..cursor + hash_size].to_vec();
        cursor += hash_size;
        let rsp_nonce: [u8; 32] = response.payload[cursor..cursor + 32].try_into().unwrap();
        cursor += 32;
        let measurement_summary_hash = response.payload[cursor..cursor + hash_size].to_vec();
        cursor += hash_size;
        let opaque_len =
            u16::from_le_bytes(response.payload[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2;
        if response.payload.len() < cursor + opaque_len + signature_size {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "challenge opaque/signature",
            ));
        }
        let opaque_data = response.payload[cursor..cursor + opaque_len].to_vec();
        cursor += opaque_len;
        let signature = response.payload[cursor..].to_vec();
        Ok(SpdmChallengeAuth {
            slot_id: response.param1 & 0x0f,
            slot_mask: response.param2,
            cert_chain_hash,
            nonce: rsp_nonce,
            measurement_summary_hash,
            opaque_data,
            signature,
        })
    }

    pub fn get_measurements(
        &mut self,
        attributes: u8,
        operation: u8,
        nonce: [u8; 32],
        slot_id: u8,
    ) -> io::Result<SpdmMeasurementRecord> {
        let version = self.negotiated_version.unwrap_or(SPDM_VERSION_12);
        let mut payload = Vec::with_capacity(33);
        payload.extend_from_slice(&nonce);
        payload.push(slot_id & 0x0f);
        let response = self.exchange_frame(&SpdmFrame {
            version,
            code: SPDM_GET_MEASUREMENTS,
            param1: attributes,
            param2: operation,
            payload,
        })?;
        if response.code != SPDM_MEASUREMENTS || response.payload.len() < 4 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "unexpected measurements response",
            ));
        }
        let number_of_blocks = response.payload[0];
        let record_len = read_u24_le(&response.payload[1..4]) as usize;
        if response.payload.len() < 4 + record_len {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "short measurement record",
            ));
        }
        Ok(SpdmMeasurementRecord {
            number_of_blocks,
            slot_id: response.param2 & 0x0f,
            content_changed: (response.param2 >> 4) & 0x03,
            measurement_record: response.payload[4..4 + record_len].to_vec(),
            signed_tail: response.payload[4 + record_len..].to_vec(),
        })
    }

    pub fn key_exchange(
        &mut self,
        request: &SpdmKeyExchangeRequest,
    ) -> io::Result<SpdmKeyExchangeResponse> {
        let version = self.negotiated_version.unwrap_or(SPDM_VERSION_12);
        let hash_size = self.negotiated_hash_size().ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidData, "hash algorithm not negotiated")
        })?;
        let signature_size = self.negotiated_signature_size().ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidData, "signature algorithm not negotiated")
        })?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&request.req_session_id.to_le_bytes());
        payload.push(request.session_policy);
        payload.push(0);
        payload.extend_from_slice(&request.random_data);
        payload.extend_from_slice(&request.exchange_data);
        payload.extend_from_slice(&(request.opaque_data.len() as u16).to_le_bytes());
        payload.extend_from_slice(&request.opaque_data);
        let response = self.exchange_frame(&SpdmFrame {
            version,
            code: SPDM_KEY_EXCHANGE,
            param1: request.measurement_summary_hash_type,
            param2: request.slot_id & 0x0f,
            payload,
        })?;
        if response.code != SPDM_KEY_EXCHANGE_RSP || response.payload.len() < 36 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "unexpected key exchange response",
            ));
        }
        let mut cursor = 0usize;
        let rsp_session_id =
            u16::from_le_bytes(response.payload[cursor..cursor + 2].try_into().unwrap());
        cursor += 2;
        let mut_auth_requested = response.payload[cursor];
        cursor += 1;
        let req_slot_id_param = response.payload[cursor];
        cursor += 1;
        let random_data: [u8; 32] = response.payload[cursor..cursor + 32].try_into().unwrap();
        cursor += 32;
        let exchange_len = request
            .responder_exchange_data_len
            .unwrap_or_else(|| negotiated_exchange_size(self.algorithms.as_ref()).unwrap_or(0));
        if response.payload.len()
            < cursor + exchange_len + hash_size + 2 + signature_size + hash_size
        {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "short key exchange tail",
            ));
        }
        let exchange_data = response.payload[cursor..cursor + exchange_len].to_vec();
        cursor += exchange_len;
        let measurement_summary_hash = response.payload[cursor..cursor + hash_size].to_vec();
        cursor += hash_size;
        let opaque_len =
            u16::from_le_bytes(response.payload[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2;
        if response.payload.len() < cursor + opaque_len + signature_size + hash_size {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "key exchange opaque/signature",
            ));
        }
        let opaque_data = response.payload[cursor..cursor + opaque_len].to_vec();
        cursor += opaque_len;
        let signature = response.payload[cursor..cursor + signature_size].to_vec();
        cursor += signature_size;
        let verify_data = response.payload[cursor..cursor + hash_size].to_vec();
        Ok(SpdmKeyExchangeResponse {
            heartbeat_period: response.param1,
            rsp_session_id,
            mut_auth_requested,
            req_slot_id_param,
            random_data,
            exchange_data,
            measurement_summary_hash,
            opaque_data,
            signature,
            verify_data,
        })
    }

    pub fn finish(
        &mut self,
        req_slot_id: u8,
        signature: &[u8],
        verify_data: &[u8],
    ) -> io::Result<SpdmFinishResponse> {
        let version = self.negotiated_version.unwrap_or(SPDM_VERSION_12);
        let mut payload = Vec::with_capacity(signature.len() + verify_data.len());
        payload.extend_from_slice(signature);
        payload.extend_from_slice(verify_data);
        let response = self.exchange_frame(&SpdmFrame {
            version,
            code: SPDM_FINISH,
            param1: if signature.is_empty() { 0 } else { 1 },
            param2: req_slot_id & 0x0f,
            payload,
        })?;
        if response.code != SPDM_FINISH_RSP {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "unexpected finish response",
            ));
        }
        let hash_size = self.negotiated_hash_size().ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidData, "hash algorithm not negotiated")
        })?;
        if response.payload.len() < hash_size {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "short finish response",
            ));
        }
        let opaque_len = response.payload.len().saturating_sub(hash_size);
        Ok(SpdmFinishResponse {
            opaque_data: response.payload[..opaque_len].to_vec(),
            verify_data: response.payload[opaque_len..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AerCounters {
    pub correctable: u64,
    pub nonfatal: u64,
    pub fatal: u64,
}

pub struct AerSysfs {
    root: PathBuf,
    bdf: PciBdf,
}

impl AerSysfs {
    pub fn new(bdf: PciBdf) -> Self {
        Self::with_root(Path::new("/sys/bus/pci/devices"), bdf)
    }

    pub fn with_root(root: &Path, bdf: PciBdf) -> Self {
        Self {
            root: root.to_path_buf(),
            bdf,
        }
    }

    fn read_counter(&self, name: &str) -> io::Result<u64> {
        let path = self.root.join(self.bdf.sysfs_name()).join(name);
        let content = fs::read_to_string(path)?;
        content
            .trim()
            .parse::<u64>()
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "aer counter"))
    }

    pub fn read(&self) -> io::Result<AerCounters> {
        Ok(AerCounters {
            correctable: self.read_counter("aer_dev_correctable")?,
            nonfatal: self.read_counter("aer_dev_nonfatal")?,
            fatal: self.read_counter("aer_dev_fatal")?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DpcStatus {
    pub control: u16,
    pub status: u16,
    pub source_id: u16,
    pub rp_pio_status: u32,
    pub header_log: [u32; 4],
}

impl DpcStatus {
    pub fn severity(&self) -> AerSeverity {
        let trigger_reason = self.status & 0x0006;
        if (self.status & 0x0001) == 0 {
            return AerSeverity::Correctable;
        }
        match trigger_reason {
            0x0002 => AerSeverity::NonFatal,
            0x0004 => AerSeverity::Fatal,
            _ => AerSeverity::DpcContainment,
        }
    }

    pub fn as_aer_event(&self) -> AerEvent {
        AerEvent {
            severity: self.severity(),
            source_id: self.source_id,
            status: self.rp_pio_status,
            header_log: self.header_log,
        }
    }
}

pub struct DpcBackend<'a> {
    device: &'a SysfsPciDevice,
    offset: u16,
}

impl<'a> DpcBackend<'a> {
    pub fn new(device: &'a SysfsPciDevice, offset: u16) -> Self {
        Self { device, offset }
    }

    pub fn new_auto(device: &'a SysfsPciDevice) -> io::Result<Option<Self>> {
        Ok(device
            .dpc_cap_offset()?
            .map(|offset| Self::new(device, offset)))
    }

    fn reg(&self, offset: u16) -> u16 {
        self.offset + offset
    }

    pub fn read_status(&self) -> io::Result<DpcStatus> {
        let mut header_log = [0u32; 4];
        for (index, slot) in header_log.iter_mut().enumerate() {
            *slot = self
                .device
                .read_config_u32(self.reg(PCI_EXP_DPC_RP_PIO_HEADER_LOG + (index as u16 * 4)))?;
        }
        Ok(DpcStatus {
            control: self.device.read_config_u16(self.reg(PCI_EXP_DPC_CTL))?,
            status: self.device.read_config_u16(self.reg(PCI_EXP_DPC_STATUS))?,
            source_id: self
                .device
                .read_config_u16(self.reg(PCI_EXP_DPC_SOURCE_ID))?,
            rp_pio_status: self
                .device
                .read_config_u32(self.reg(PCI_EXP_DPC_RP_PIO_STATUS))?,
            header_log,
        })
    }

    pub fn containment_decision(&self) -> io::Result<ContainmentDecision> {
        Ok(containment_decision(self.read_status()?.as_aer_event()))
    }

    pub fn recover_if_needed(&self) -> io::Result<ContainmentDecision> {
        let decision = self.containment_decision()?;
        if matches!(decision, ContainmentDecision::ResetRequired) {
            self.device.reset()?;
        }
        Ok(decision)
    }
}

pub struct SriovManager {
    root: PathBuf,
    bdf: PciBdf,
}

impl SriovManager {
    pub fn new(bdf: PciBdf) -> Self {
        Self::with_root(Path::new("/sys/bus/pci/devices"), bdf)
    }

    pub fn with_root(root: &Path, bdf: PciBdf) -> Self {
        Self {
            root: root.to_path_buf(),
            bdf,
        }
    }

    fn device_dir(&self) -> PathBuf {
        self.root.join(self.bdf.sysfs_name())
    }

    fn read_u16_file(&self, name: &str) -> io::Result<u16> {
        let content = fs::read_to_string(self.device_dir().join(name))?;
        content
            .trim()
            .parse::<u16>()
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "sr-iov value"))
    }

    fn write_u16_file(&self, name: &str, value: u16) -> io::Result<()> {
        fs::write(self.device_dir().join(name), std::format!("{value}\n"))
    }

    pub fn total_vfs(&self) -> io::Result<u16> {
        self.read_u16_file("sriov_totalvfs")
    }

    pub fn enabled_vfs(&self) -> io::Result<u16> {
        self.read_u16_file("sriov_numvfs")
    }

    pub fn enable_vfs(&self, count: u16) -> io::Result<()> {
        self.write_u16_file("sriov_numvfs", count)
    }

    pub fn disable_vfs(&self) -> io::Result<()> {
        self.write_u16_file("sriov_numvfs", 0)
    }

    pub fn list_vfs(&self) -> io::Result<Vec<PciBdf>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.device_dir())? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("virtfn") {
                continue;
            }
            let target = fs::read_link(entry.path())?;
            let final_name = target
                .file_name()
                .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "virtfn target"))?;
            out.push(PciBdf::parse(&final_name.to_string_lossy())?);
        }
        out.sort_by_key(|bdf| (bdf.domain, bdf.bus, bdf.device, bdf.function));
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IommuMapFlags {
    pub readable: bool,
    pub writeable: bool,
    pub fixed_iova: bool,
}

impl IommuMapFlags {
    fn bits(self) -> u32 {
        let mut bits = 0u32;
        if self.fixed_iova {
            bits |= IOMMU_IOAS_MAP_FIXED_IOVA;
        }
        if self.writeable {
            bits |= IOMMU_IOAS_MAP_WRITEABLE;
        }
        if self.readable {
            bits |= IOMMU_IOAS_MAP_READABLE;
        }
        bits
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VtdStage1Hwpt {
    pub flags: u64,
    pub page_table_addr: u64,
    pub address_width: u32,
}

pub struct IommuFd {
    file: File,
}

impl IommuFd {
    pub fn open() -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/iommu")?;
        Ok(Self { file })
    }

    fn ioctl<T>(&self, request: c_ulong, arg: &mut T) -> io::Result<()> {
        // SAFETY: each ioctl request is paired with the matching repr(C) structure and the file
        // descriptor stays valid for the duration of the call.
        let ret = unsafe { ioctl(self.file.as_raw_fd(), request, arg) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn allocate_ioas(&self) -> io::Result<u32> {
        let mut alloc = iommu_ioas_alloc {
            size: std::mem::size_of::<iommu_ioas_alloc>() as u32,
            flags: 0,
            out_ioas_id: 0,
        };
        self.ioctl(io_request(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_ALLOC), &mut alloc)?;
        Ok(alloc.out_ioas_id)
    }

    pub fn map_user(
        &self,
        ioas_id: u32,
        user_va: u64,
        length: u64,
        iova: Option<u64>,
        flags: IommuMapFlags,
    ) -> io::Result<u64> {
        let mut map = iommu_ioas_map {
            size: std::mem::size_of::<iommu_ioas_map>() as u32,
            flags: flags.bits(),
            ioas_id,
            __reserved: 0,
            user_va,
            length,
            iova: iova.unwrap_or(0),
        };
        self.ioctl(io_request(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_MAP), &mut map)?;
        Ok(map.iova)
    }

    pub fn unmap(&self, ioas_id: u32, iova: u64, length: u64) -> io::Result<u64> {
        let mut unmap = iommu_ioas_unmap {
            size: std::mem::size_of::<iommu_ioas_unmap>() as u32,
            ioas_id,
            iova,
            length,
        };
        self.ioctl(io_request(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_UNMAP), &mut unmap)?;
        Ok(unmap.length)
    }

    pub fn allocate_hwpt(&self, dev_id: u32, pt_id: u32, pasid_mode: bool) -> io::Result<u32> {
        let mut alloc = iommu_hwpt_alloc {
            size: std::mem::size_of::<iommu_hwpt_alloc>() as u32,
            flags: if pasid_mode {
                IOMMU_HWPT_ALLOC_PASID
            } else {
                0
            },
            dev_id,
            pt_id,
            out_hwpt_id: 0,
            __reserved: 0,
            data_type: IOMMU_HWPT_DATA_NONE,
            data_len: 0,
            data_uptr: 0,
            fault_id: 0,
            __reserved2: 0,
        };
        self.ioctl(io_request(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_ALLOC), &mut alloc)?;
        Ok(alloc.out_hwpt_id)
    }

    pub fn allocate_vtd_stage1_hwpt(
        &self,
        dev_id: u32,
        parent_pt_id: u32,
        spec: VtdStage1Hwpt,
        pasid_mode: bool,
    ) -> io::Result<u32> {
        let mut data = iommu_hwpt_vtd_s1 {
            flags: spec.flags,
            pgtbl_addr: spec.page_table_addr,
            addr_width: spec.address_width,
            __reserved: 0,
        };
        let mut alloc = iommu_hwpt_alloc {
            size: std::mem::size_of::<iommu_hwpt_alloc>() as u32,
            flags: if pasid_mode {
                IOMMU_HWPT_ALLOC_PASID
            } else {
                0
            },
            dev_id,
            pt_id: parent_pt_id,
            out_hwpt_id: 0,
            __reserved: 0,
            data_type: IOMMU_HWPT_DATA_VTD_S1,
            data_len: std::mem::size_of::<iommu_hwpt_vtd_s1>() as u32,
            data_uptr: (&mut data as *mut iommu_hwpt_vtd_s1) as u64,
            fault_id: 0,
            __reserved2: 0,
        };
        self.ioctl(io_request(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_ALLOC), &mut alloc)?;
        Ok(alloc.out_hwpt_id)
    }

    pub fn invalidate_vtd_stage1(
        &self,
        hwpt_id: u32,
        addr: u64,
        npages: u64,
        leaf_only: bool,
    ) -> io::Result<u32> {
        let mut entry = iommu_hwpt_vtd_s1_invalidate {
            addr,
            npages,
            flags: if leaf_only {
                IOMMU_VTD_INV_FLAGS_LEAF
            } else {
                0
            },
            __reserved: 0,
        };
        let mut invalidate = iommu_hwpt_invalidate {
            size: std::mem::size_of::<iommu_hwpt_invalidate>() as u32,
            hwpt_id,
            data_uptr: (&mut entry as *mut iommu_hwpt_vtd_s1_invalidate) as u64,
            data_type: IOMMU_HWPT_INVALIDATE_DATA_VTD_S1,
            entry_len: std::mem::size_of::<iommu_hwpt_vtd_s1_invalidate>() as u32,
            entry_num: 1,
            __reserved: 0,
        };
        self.ioctl(
            io_request(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_INVALIDATE),
            &mut invalidate,
        )?;
        Ok(invalidate.entry_num)
    }
}

pub struct VfioDevice {
    file: File,
}

impl VfioDevice {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(Self { file })
    }

    pub fn bind_iommufd(&self, iommu: &IommuFd, token: Option<[u8; 16]>) -> io::Result<u32> {
        let mut token_copy = token.unwrap_or([0u8; 16]);
        let mut bind = vfio_device_bind_iommufd {
            argsz: std::mem::size_of::<vfio_device_bind_iommufd>() as u32,
            flags: if token.is_some() {
                VFIO_DEVICE_BIND_FLAG_TOKEN
            } else {
                0
            },
            iommufd: iommu.file.as_raw_fd(),
            out_devid: 0,
            token_uuid_ptr: if token.is_some() {
                token_copy.as_mut_ptr() as u64
            } else {
                0
            },
        };
        // SAFETY: the ioctl request and structure match the VFIO UAPI and the fd remains valid.
        let ret = unsafe {
            ioctl(
                self.file.as_raw_fd(),
                io_request(VFIO_TYPE, VFIO_DEVICE_BIND_IOMMUFD_NR),
                &mut bind,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(bind.out_devid)
    }

    pub fn attach_hwpt(&self, pt_id: u32, pasid: Option<u32>) -> io::Result<u32> {
        let mut attach = vfio_device_attach_iommufd_pt {
            argsz: std::mem::size_of::<vfio_device_attach_iommufd_pt>() as u32,
            flags: if pasid.is_some() {
                VFIO_DEVICE_ATTACH_PASID
            } else {
                0
            },
            pt_id,
            pasid: pasid.unwrap_or(0),
        };
        // SAFETY: the ioctl request and structure match the VFIO UAPI and the fd remains valid.
        let ret = unsafe {
            ioctl(
                self.file.as_raw_fd(),
                io_request(VFIO_TYPE, VFIO_DEVICE_ATTACH_IOMMUFD_PT_NR),
                &mut attach,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(attach.pt_id)
    }

    pub fn detach_hwpt(&self, pasid: Option<u32>) -> io::Result<()> {
        let mut detach = vfio_device_detach_iommufd_pt {
            argsz: std::mem::size_of::<vfio_device_detach_iommufd_pt>() as u32,
            flags: if pasid.is_some() {
                VFIO_DEVICE_DETACH_PASID
            } else {
                0
            },
            pasid: pasid.unwrap_or(0),
        };
        // SAFETY: the ioctl request and structure match the VFIO UAPI and the fd remains valid.
        let ret = unsafe {
            ioctl(
                self.file.as_raw_fd(),
                io_request(VFIO_TYPE, VFIO_DEVICE_DETACH_IOMMUFD_PT_NR),
                &mut detach,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn encode_spdm_frame(frame: &SpdmFrame) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + frame.payload.len());
    out.push(frame.version);
    out.push(frame.code);
    out.push(frame.param1);
    out.push(frame.param2);
    out.extend_from_slice(&frame.payload);
    out
}

fn decode_spdm_frame(bytes: &[u8]) -> io::Result<SpdmFrame> {
    if bytes.len() < 4 {
        return Err(io::Error::new(ErrorKind::UnexpectedEof, "short spdm frame"));
    }
    Ok(SpdmFrame {
        version: bytes[0],
        code: bytes[1],
        param1: bytes[2],
        param2: bytes[3],
        payload: bytes[4..].to_vec(),
    })
}

fn parse_versions(frame: &SpdmFrame) -> io::Result<Option<SpdmVersionSet>> {
    if frame.code != SPDM_VERSION {
        return Ok(None);
    }
    if frame.payload.len() < 2 {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "short version payload",
        ));
    }
    let count = frame.payload[1] as usize;
    if frame.payload.len() < 2 + count * 2 {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "short version entries",
        ));
    }
    let mut versions = Vec::with_capacity(count);
    let mut cursor = 2usize;
    for _ in 0..count {
        let version_word =
            u16::from_le_bytes(frame.payload[cursor..cursor + 2].try_into().unwrap());
        versions.push((version_word >> 8) as u8);
        cursor += 2;
    }
    Ok(Some(SpdmVersionSet { versions }))
}

fn encode_algorithm_table(table: &SpdmAlgorithmTable) -> io::Result<Vec<u8>> {
    if table.fixed_algorithms.len() > 0x0f || table.external_algorithms.len() > 0x0f {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "too many algorithm entries",
        ));
    }
    let mut out =
        Vec::with_capacity(2 + table.fixed_algorithms.len() + table.external_algorithms.len() * 4);
    let alg_count =
        (table.external_algorithms.len() as u8) | ((table.fixed_algorithms.len() as u8) << 4);
    out.push(table.alg_type);
    out.push(alg_count);
    out.extend_from_slice(&table.fixed_algorithms);
    for ext in &table.external_algorithms {
        out.extend_from_slice(&ext.to_le_bytes());
    }
    Ok(out)
}

fn decode_algorithm_tables(count: u8, payload: &[u8]) -> io::Result<Vec<SpdmAlgorithmTable>> {
    let mut out = Vec::with_capacity(count as usize);
    let mut cursor = 0usize;
    for _ in 0..count {
        if payload.len() < cursor + 2 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "algorithm table header",
            ));
        }
        let alg_type = payload[cursor];
        let alg_count = payload[cursor + 1];
        cursor += 2;
        let fixed_len = ((alg_count >> 4) & 0x0f) as usize;
        let ext_len = (alg_count & 0x0f) as usize;
        if payload.len() < cursor + fixed_len + ext_len * 4 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "algorithm table body",
            ));
        }
        let fixed_algorithms = payload[cursor..cursor + fixed_len].to_vec();
        cursor += fixed_len;
        let mut external_algorithms = Vec::with_capacity(ext_len);
        for _ in 0..ext_len {
            external_algorithms.push(u32::from_le_bytes(
                payload[cursor..cursor + 4].try_into().unwrap(),
            ));
            cursor += 4;
        }
        out.push(SpdmAlgorithmTable {
            alg_type,
            fixed_algorithms,
            external_algorithms,
        });
    }
    Ok(out)
}

fn read_u24_le(bytes: &[u8]) -> u32 {
    (bytes[0] as u32) | ((bytes[1] as u32) << 8) | ((bytes[2] as u32) << 16)
}

fn hash_size_from_algo(base_hash_sel: u32) -> usize {
    if (base_hash_sel & 0x0000_0001) != 0 || (base_hash_sel & 0x0000_0008) != 0 {
        32
    } else if (base_hash_sel & 0x0000_0002) != 0 || (base_hash_sel & 0x0000_0010) != 0 {
        48
    } else if (base_hash_sel & 0x0000_0004) != 0 || (base_hash_sel & 0x0000_0020) != 0 {
        64
    } else {
        32
    }
}

fn signature_size_from_asym(base_asym_sel: u32) -> usize {
    if (base_asym_sel & 0x0000_0001) != 0 || (base_asym_sel & 0x0000_0002) != 0 {
        256
    } else if (base_asym_sel & 0x0000_0004) != 0 || (base_asym_sel & 0x0000_0008) != 0 {
        384
    } else if (base_asym_sel & 0x0000_0020) != 0 || (base_asym_sel & 0x0000_0040) != 0 {
        512
    } else if (base_asym_sel & 0x0000_0010) != 0 || (base_asym_sel & 0x0000_0200) != 0 {
        64
    } else if (base_asym_sel & 0x0000_0080) != 0 {
        96
    } else if (base_asym_sel & 0x0000_0100) != 0 {
        132
    } else if (base_asym_sel & 0x0000_0400) != 0 {
        64
    } else if (base_asym_sel & 0x0000_0800) != 0 {
        114
    } else {
        64
    }
}

fn negotiated_exchange_size(algorithms: Option<&SpdmAlgorithms>) -> Option<usize> {
    let algorithms = algorithms?;
    for table in &algorithms.tables {
        if table.alg_type != 2 || table.fixed_algorithms.len() < 2 {
            continue;
        }
        let selected = u16::from_le_bytes([table.fixed_algorithms[0], table.fixed_algorithms[1]]);
        return Some(match selected {
            0x0001 => 256,
            0x0002 => 384,
            0x0004 => 512,
            0x0008 => 65,
            0x0010 => 97,
            0x0020 => 133,
            0x0040 => 65,
            _ => 0,
        });
    }
    None
}

fn bytes_to_dwords(bytes: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity((bytes.len() + 3) / 4);
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let mut word = [0u8; 4];
        let take = (bytes.len() - cursor).min(4);
        word[..take].copy_from_slice(&bytes[cursor..cursor + take]);
        out.push(u32::from_le_bytes(word));
        cursor += take;
    }
    out
}

fn dwords_to_bytes(words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 4);
    for word in words {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

const fn io_request(ty: u8, nr: u8) -> c_ulong {
    ((ty as c_ulong) << 8) | nr as c_ulong
}

#[repr(C)]
struct iommu_ioas_alloc {
    size: u32,
    flags: u32,
    out_ioas_id: u32,
}

#[repr(C)]
struct iommu_ioas_map {
    size: u32,
    flags: u32,
    ioas_id: u32,
    __reserved: u32,
    user_va: u64,
    length: u64,
    iova: u64,
}

#[repr(C)]
struct iommu_ioas_unmap {
    size: u32,
    ioas_id: u32,
    iova: u64,
    length: u64,
}

#[repr(C)]
struct iommu_hwpt_vtd_s1 {
    flags: u64,
    pgtbl_addr: u64,
    addr_width: u32,
    __reserved: u32,
}

#[repr(C)]
struct iommu_hwpt_alloc {
    size: u32,
    flags: u32,
    dev_id: u32,
    pt_id: u32,
    out_hwpt_id: u32,
    __reserved: u32,
    data_type: u32,
    data_len: u32,
    data_uptr: u64,
    fault_id: u32,
    __reserved2: u32,
}

#[repr(C)]
struct iommu_hwpt_vtd_s1_invalidate {
    addr: u64,
    npages: u64,
    flags: u32,
    __reserved: u32,
}

#[repr(C)]
struct iommu_hwpt_invalidate {
    size: u32,
    hwpt_id: u32,
    data_uptr: u64,
    data_type: u32,
    entry_len: u32,
    entry_num: u32,
    __reserved: u32,
}

#[repr(C)]
struct vfio_device_bind_iommufd {
    argsz: u32,
    flags: u32,
    iommufd: i32,
    out_devid: u32,
    token_uuid_ptr: u64,
}

#[repr(C)]
struct vfio_device_attach_iommufd_pt {
    argsz: u32,
    flags: u32,
    pt_id: u32,
    pasid: u32,
}

#[repr(C)]
struct vfio_device_detach_iommufd_pt {
    argsz: u32,
    flags: u32,
    pasid: u32,
}

#[cfg(test)]
mod tests {
    use super::{
        AerSysfs, DoeMailbox, DpcBackend, IommuFd, IommuMapFlags, PciBdf, SpdmAlgorithmTable,
        SpdmNegotiateAlgorithmsRequest, SpdmRequester, SriovManager, SysfsPciDevice, VfioDevice,
        PCI_EXP_DPC_CTL, PCI_EXP_DPC_RP_PIO_HEADER_LOG, PCI_EXP_DPC_RP_PIO_STATUS,
        PCI_EXP_DPC_SOURCE_ID,
    };
    use std::fs::{self, File};
    use std::io::{Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::vec;
    use std::vec::Vec;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_temp_dir(name: &str) -> PathBuf {
        let suffix = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(std::format!("ironshim-{name}-{suffix}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_config(root: &Path, bdf: PciBdf, configure: impl FnOnce(&mut File)) {
        let device_dir = root.join(bdf.sysfs_name());
        fs::create_dir_all(&device_dir).unwrap();
        let mut config = File::create(device_dir.join("config")).unwrap();
        config.set_len(4096).unwrap();
        configure(&mut config);
    }

    fn write_dword(file: &mut File, offset: u64, value: u32) {
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&value.to_le_bytes()).unwrap();
    }

    fn ext_cap(id: u16, next: u16) -> u32 {
        id as u32 | ((1u32) << 16) | ((next as u32) << 20)
    }

    fn negotiate_request() -> SpdmNegotiateAlgorithmsRequest {
        SpdmNegotiateAlgorithmsRequest {
            measurement_specification: 0x01,
            other_params_support: 0x02,
            base_asym_algo: 0x0000_0fff,
            base_hash_algo: 0x0000_007f,
            pqc_asym_algo: 0,
            mel_specification: 0,
            tables: vec![
                SpdmAlgorithmTable {
                    alg_type: 2,
                    fixed_algorithms: 0x007f_u16.to_le_bytes().to_vec(),
                    external_algorithms: Vec::new(),
                },
                SpdmAlgorithmTable {
                    alg_type: 3,
                    fixed_algorithms: 0x000f_u16.to_le_bytes().to_vec(),
                    external_algorithms: Vec::new(),
                },
                SpdmAlgorithmTable {
                    alg_type: 4,
                    fixed_algorithms: 0x0fff_u16.to_le_bytes().to_vec(),
                    external_algorithms: Vec::new(),
                },
                SpdmAlgorithmTable {
                    alg_type: 5,
                    fixed_algorithms: 0x0001_u16.to_le_bytes().to_vec(),
                    external_algorithms: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn sysfs_pci_device_discovers_caps() {
        let root = make_temp_dir("caps");
        let bdf = PciBdf::parse("0000:00:1f.0").unwrap();
        write_config(&root, bdf, |config| {
            write_dword(config, 0x100, ext_cap(0x10, 0x120));
            write_dword(config, 0x120, ext_cap(0x2e, 0));
        });
        let device = SysfsPciDevice::open_with_root(&root, bdf).unwrap();
        assert_eq!(device.sriov_cap_offset().unwrap(), Some(0x100));
        assert_eq!(device.doe_cap_offset().unwrap(), Some(0x120));
    }

    #[test]
    fn sriov_manager_reads_sysfs_vfs() {
        let root = make_temp_dir("sriov");
        let pf = PciBdf::parse("0000:03:00.0").unwrap();
        let vf = PciBdf::parse("0000:03:00.1").unwrap();
        let pf_dir = root.join(pf.sysfs_name());
        fs::create_dir_all(&pf_dir).unwrap();
        fs::create_dir_all(root.join(vf.sysfs_name())).unwrap();
        fs::write(pf_dir.join("sriov_totalvfs"), "8\n").unwrap();
        fs::write(pf_dir.join("sriov_numvfs"), "2\n").unwrap();
        std::os::unix::fs::symlink(root.join(vf.sysfs_name()), pf_dir.join("virtfn0")).unwrap();

        let manager = SriovManager::with_root(&root, pf);
        assert_eq!(manager.total_vfs().unwrap(), 8);
        assert_eq!(manager.enabled_vfs().unwrap(), 2);
        assert_eq!(manager.list_vfs().unwrap(), vec![vf]);
    }

    #[test]
    fn aer_sysfs_reads_counters() {
        let root = make_temp_dir("aer");
        let bdf = PciBdf::parse("0000:04:00.0").unwrap();
        let device_dir = root.join(bdf.sysfs_name());
        fs::create_dir_all(&device_dir).unwrap();
        fs::write(device_dir.join("aer_dev_correctable"), "1\n").unwrap();
        fs::write(device_dir.join("aer_dev_nonfatal"), "2\n").unwrap();
        fs::write(device_dir.join("aer_dev_fatal"), "3\n").unwrap();

        let counters = AerSysfs::with_root(&root, bdf).read().unwrap();
        assert_eq!(counters.correctable, 1);
        assert_eq!(counters.nonfatal, 2);
        assert_eq!(counters.fatal, 3);
    }

    #[test]
    fn dpc_backend_reads_status_block() {
        let root = make_temp_dir("dpc");
        let bdf = PciBdf::parse("0000:05:00.0").unwrap();
        write_config(&root, bdf, |config| {
            write_dword(config, 0x100, ext_cap(0x1d, 0));
            write_dword(config, 0x100 + PCI_EXP_DPC_CTL as u64, 0x0003_0007);
            write_dword(config, 0x100 + PCI_EXP_DPC_SOURCE_ID as u64, 0x1234_00aa);
            write_dword(
                config,
                0x100 + PCI_EXP_DPC_RP_PIO_STATUS as u64,
                0xfeed_beef,
            );
            for idx in 0..4u64 {
                write_dword(
                    config,
                    0x100 + PCI_EXP_DPC_RP_PIO_HEADER_LOG as u64 + idx * 4,
                    0x1000 + idx as u32,
                );
            }
        });

        let device = SysfsPciDevice::open_with_root(&root, bdf).unwrap();
        let backend = DpcBackend::new_auto(&device).unwrap().unwrap();
        let status = backend.read_status().unwrap();
        assert_eq!(status.control, 0x0007);
        assert_eq!(status.status, 0x0003);
        assert_eq!(status.source_id, 0x00aa);
        assert_eq!(status.rp_pio_status, 0xfeed_beef);
        assert_eq!(status.header_log, [0x1000, 0x1001, 0x1002, 0x1003]);
    }

    #[test]
    fn live_spdm_smoke_if_requested() {
        let Ok(bdf) = std::env::var("IRONSHIM_LIVE_SPDM_BDF") else {
            return;
        };
        let device = SysfsPciDevice::open(PciBdf::parse(&bdf).unwrap()).unwrap();
        let mailbox = DoeMailbox::new_auto(&device)
            .unwrap()
            .expect("DOE capability");
        let mut requester = SpdmRequester::new_cma_spdm(mailbox);
        let _versions = requester.get_versions().unwrap();
        let caps = requester
            .get_capabilities(0, 0x8002_E2C6, 4096, 4096)
            .unwrap();
        let _algorithms = requester
            .negotiate_algorithms(&negotiate_request())
            .unwrap();
        if (caps.flags & 0x0000_0002) != 0 {
            let digests = requester.get_digests().unwrap();
            let slot = digests.provisioned_slot_mask.trailing_zeros() as u8;
            let _certificate = requester.get_certificate(slot, 1024).unwrap();
            if (caps.flags & 0x0000_0004) != 0 {
                let _challenge = requester.challenge(slot, 0, [0xA5; 32]).unwrap();
            }
        }
        if (caps.flags & 0x0000_0018) != 0 || (caps.flags & 0x0000_0020) != 0 {
            let _measurements = requester.get_measurements(0, 0xFF, [0x5A; 32], 0).unwrap();
        }
    }

    #[test]
    fn live_iommufd_vfio_roundtrip_if_requested() {
        let Ok(vfio_path) = std::env::var("IRONSHIM_LIVE_VFIO_CDEV") else {
            return;
        };
        let iommu = IommuFd::open().unwrap();
        let vfio = VfioDevice::open(vfio_path).unwrap();
        let _dev_id = vfio.bind_iommufd(&iommu, None).unwrap();
        let ioas = iommu.allocate_ioas().unwrap();
        let pasid = std::env::var("IRONSHIM_LIVE_PASID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok());
        let _pt_id = vfio.attach_hwpt(ioas, pasid).unwrap();
        let mut backing = vec![0u8; 4096];
        let iova = iommu
            .map_user(
                ioas,
                backing.as_mut_ptr() as u64,
                backing.len() as u64,
                None,
                IommuMapFlags {
                    readable: true,
                    writeable: true,
                    fixed_iova: false,
                },
            )
            .unwrap();
        assert!(iova != 0);
        let unmapped = iommu.unmap(ioas, iova, backing.len() as u64).unwrap();
        assert_eq!(unmapped, backing.len() as u64);
        vfio.detach_hwpt(pasid).unwrap();
    }

    #[test]
    fn live_dpc_recovery_if_requested() {
        let Ok(bdf) = std::env::var("IRONSHIM_LIVE_DPC_BDF") else {
            return;
        };
        let device = SysfsPciDevice::open(PciBdf::parse(&bdf).unwrap()).unwrap();
        if let Some(backend) = DpcBackend::new_auto(&device).unwrap() {
            let _ = backend.containment_decision().unwrap();
            if std::env::var("IRONSHIM_LIVE_DPC_RECOVER").ok().as_deref() == Some("1") {
                let _ = backend.recover_if_needed().unwrap();
            }
        }
        let _ = AerSysfs::new(PciBdf::parse(&bdf).unwrap()).read();
    }

    #[test]
    fn live_sriov_inventory_if_requested() {
        let Ok(bdf) = std::env::var("IRONSHIM_LIVE_SRIOV_BDF") else {
            return;
        };
        let manager = SriovManager::new(PciBdf::parse(&bdf).unwrap());
        let _ = manager.total_vfs().unwrap();
        let _ = manager.enabled_vfs().unwrap();
        let _ = manager.list_vfs();
    }
}
