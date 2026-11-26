//! Zero-dependency Protobuf v3 wire codec with exact CSI v1.9 (`csi.v1.*`) field numbers
//! and gRPC 5-byte message framing (`<= 4 MiB`).

use crate::spec::*;
use std::collections::BTreeMap;

/// Maximum gRPC message payload size (`4 MiB`).
pub const MAX_GRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

// Wire types
const WIRE_VARINT: u32 = 0;
const WIRE_I64: u32 = 1;
const WIRE_LEN: u32 = 2;
const WIRE_I32: u32 = 5;

/// Wrap a serialized protobuf message in a 5-byte gRPC frame (`compressed=0 || len:u32 BE || body`).
pub fn encode_grpc_frame(msg: &[u8]) -> CsiResult<Vec<u8>> {
    if msg.len() > MAX_GRPC_MESSAGE_BYTES {
        return Err(CsiError::resource_exhausted("gRPC message exceeds 4 MiB"));
    }
    let mut out = Vec::with_capacity(5 + msg.len());
    out.push(0); // uncompressed
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    Ok(out)
}

/// Unwrap one 5-byte gRPC frame from `bytes`, enforcing `compressed == 0` and `<= 4 MiB`.
pub fn decode_grpc_frame(bytes: &[u8]) -> CsiResult<&[u8]> {
    if bytes.len() < 5 {
        return Err(CsiError::invalid_argument("truncated gRPC frame header"));
    }
    let compressed = bytes[0];
    if compressed != 0 {
        return Err(CsiError::unimplemented("gRPC compression not supported"));
    }
    let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    if len > MAX_GRPC_MESSAGE_BYTES {
        return Err(CsiError::resource_exhausted("gRPC message exceeds 4 MiB"));
    }
    if bytes.len() != 5 + len {
        return Err(CsiError::invalid_argument("gRPC frame length mismatch"));
    }
    Ok(&bytes[5..])
}

// ---------------------------------------------------------------------------
// Low-level Protobuf v3 encoder/decoder primitives
// ---------------------------------------------------------------------------

pub struct PbEncoder {
    buf: Vec<u8>,
}

impl Default for PbEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl PbEncoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    fn write_varint(&mut self, mut v: u64) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            self.buf.push(b);
            if v == 0 {
                break;
            }
        }
    }

    fn write_tag(&mut self, field: u32, wire: u32) {
        self.write_varint(u64::from((field << 3) | wire));
    }

    pub fn write_u32(&mut self, field: u32, val: u32) {
        if val != 0 {
            self.write_tag(field, WIRE_VARINT);
            self.write_varint(u64::from(val));
        }
    }

    pub fn write_i32(&mut self, field: u32, val: i32) {
        if val != 0 {
            self.write_tag(field, WIRE_VARINT);
            self.write_varint(val as i64 as u64);
        }
    }

    pub fn write_i64(&mut self, field: u32, val: i64) {
        if val != 0 {
            self.write_tag(field, WIRE_VARINT);
            self.write_varint(val as u64);
        }
    }

    pub fn write_bool(&mut self, field: u32, val: bool) {
        if val {
            self.write_tag(field, WIRE_VARINT);
            self.write_varint(1);
        }
    }

    pub fn write_bool_always(&mut self, field: u32, val: bool) {
        self.write_tag(field, WIRE_VARINT);
        self.write_varint(u64::from(val));
    }

    pub fn write_string(&mut self, field: u32, val: &str) {
        if !val.is_empty() {
            self.write_bytes_always(field, val.as_bytes());
        }
    }

    pub fn write_bytes_always(&mut self, field: u32, val: &[u8]) {
        self.write_tag(field, WIRE_LEN);
        self.write_varint(val.len() as u64);
        self.buf.extend_from_slice(val);
    }

    pub fn write_message(&mut self, field: u32, msg: &[u8]) {
        self.write_bytes_always(field, msg);
    }

    pub fn write_map(&mut self, field: u32, map: &BTreeMap<String, String>) {
        for (k, v) in map {
            let mut entry = PbEncoder::new();
            entry.write_string(1, k);
            entry.write_string(2, v);
            self.write_message(field, &entry.into_bytes());
        }
    }
}

pub struct PbDecoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> PbDecoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub fn is_eof(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    pub fn read_varint(&mut self) -> CsiResult<u64> {
        let mut out = 0u64;
        let mut shift = 0u32;
        for _ in 0..10 {
            if self.pos >= self.bytes.len() {
                return Err(CsiError::invalid_argument("truncated protobuf varint"));
            }
            let b = self.bytes[self.pos];
            self.pos += 1;
            out |= u64::from(b & 0x7f) << shift;
            if (b & 0x80) == 0 {
                return Ok(out);
            }
            shift += 7;
        }
        Err(CsiError::invalid_argument("protobuf varint overflow"))
    }

    pub fn next_tag(&mut self) -> CsiResult<Option<(u32, u32)>> {
        if self.is_eof() {
            return Ok(None);
        }
        let raw = self.read_varint()?;
        let field = u32::try_from(raw >> 3)
            .map_err(|_| CsiError::invalid_argument("protobuf field number overflow"))?;
        let wire = (raw & 0x07) as u32;
        if field == 0 {
            return Err(CsiError::invalid_argument("protobuf field number 0"));
        }
        Ok(Some((field, wire)))
    }

    pub fn read_bytes(&mut self) -> CsiResult<&'a [u8]> {
        let len = usize::try_from(self.read_varint()?)
            .map_err(|_| CsiError::invalid_argument("protobuf length overflow"))?;
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| CsiError::invalid_argument("protobuf slice overflow"))?;
        if end > self.bytes.len() {
            return Err(CsiError::invalid_argument("truncated protobuf bytes"));
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn read_string(&mut self) -> CsiResult<String> {
        let slice = self.read_bytes()?;
        std::str::from_utf8(slice)
            .map(str::to_owned)
            .map_err(|_| CsiError::invalid_argument("non-UTF8 protobuf string"))
    }

    pub fn skip_field(&mut self, wire: u32) -> CsiResult<()> {
        match wire {
            WIRE_VARINT => {
                self.read_varint()?;
                Ok(())
            }
            WIRE_I64 => {
                if self.pos + 8 > self.bytes.len() {
                    return Err(CsiError::invalid_argument("truncated fixed64"));
                }
                self.pos += 8;
                Ok(())
            }
            WIRE_LEN => {
                self.read_bytes()?;
                Ok(())
            }
            WIRE_I32 => {
                if self.pos + 4 > self.bytes.len() {
                    return Err(CsiError::invalid_argument("truncated fixed32"));
                }
                self.pos += 4;
                Ok(())
            }
            _ => Err(CsiError::invalid_argument("unsupported protobuf wire type")),
        }
    }

    pub fn read_map_entry(&mut self) -> CsiResult<(String, String)> {
        let raw = self.read_bytes()?;
        let mut sub = PbDecoder::new(raw);
        let mut k = String::new();
        let mut v = String::new();
        while let Some((f, w)) = sub.next_tag()? {
            match (f, w) {
                (1, WIRE_LEN) => k = sub.read_string()?,
                (2, WIRE_LEN) => v = sub.read_string()?,
                _ => sub.skip_field(w)?,
            }
        }
        Ok((k, v))
    }
}

// ---------------------------------------------------------------------------
// Shared nested message codecs
// ---------------------------------------------------------------------------

fn encode_capacity_range(cr: &CapacityRange) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_i64(1, cr.required_bytes);
    e.write_i64(2, cr.limit_bytes);
    e.into_bytes()
}

fn decode_capacity_range(raw: &[u8]) -> CsiResult<CapacityRange> {
    let mut d = PbDecoder::new(raw);
    let mut out = CapacityRange::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_VARINT) => out.required_bytes = d.read_varint()? as i64,
            (2, WIRE_VARINT) => out.limit_bytes = d.read_varint()? as i64,
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

fn encode_volume_capability(cap: &VolumeCapability) -> Vec<u8> {
    let mut e = PbEncoder::new();
    match &cap.access_type {
        AccessType::Block => {
            e.write_message(1, &[]);
        }
        AccessType::Mount {
            fs_type,
            mount_flags,
        } => {
            let mut m = PbEncoder::new();
            m.write_string(1, fs_type);
            for flag in mount_flags {
                m.write_string(2, flag);
            }
            e.write_message(2, &m.into_bytes());
        }
    }
    let mut am = PbEncoder::new();
    am.write_u32(1, cap.access_mode.as_u32());
    e.write_message(3, &am.into_bytes());
    e.into_bytes()
}

fn decode_volume_capability(raw: &[u8]) -> CsiResult<VolumeCapability> {
    let mut d = PbDecoder::new(raw);
    let mut out = VolumeCapability::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => {
                let _ = d.read_bytes()?;
                out.access_type = AccessType::Block;
            }
            (2, WIRE_LEN) => {
                let mb = d.read_bytes()?;
                let mut md = PbDecoder::new(mb);
                let mut fs_type = String::new();
                let mut mount_flags = Vec::new();
                while let Some((mf, mw)) = md.next_tag()? {
                    match (mf, mw) {
                        (1, WIRE_LEN) => fs_type = md.read_string()?,
                        (2, WIRE_LEN) => mount_flags.push(md.read_string()?),
                        _ => md.skip_field(mw)?,
                    }
                }
                out.access_type = AccessType::Mount {
                    fs_type,
                    mount_flags,
                };
            }
            (3, WIRE_LEN) => {
                let ab = d.read_bytes()?;
                let mut ad = PbDecoder::new(ab);
                while let Some((af, aw)) = ad.next_tag()? {
                    match (af, aw) {
                        (1, WIRE_VARINT) => {
                            out.access_mode = AccessMode::from_u32(ad.read_varint()? as u32);
                        }
                        _ => ad.skip_field(aw)?,
                    }
                }
            }
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

fn encode_content_source(src: &VolumeContentSource) -> Vec<u8> {
    let mut e = PbEncoder::new();
    match src {
        VolumeContentSource::Snapshot { snapshot_id } => {
            let mut s = PbEncoder::new();
            s.write_string(1, snapshot_id);
            e.write_message(1, &s.into_bytes());
        }
        VolumeContentSource::Volume { volume_id } => {
            let mut v = PbEncoder::new();
            v.write_string(1, volume_id);
            e.write_message(2, &v.into_bytes());
        }
    }
    e.into_bytes()
}

fn decode_content_source(raw: &[u8]) -> CsiResult<Option<VolumeContentSource>> {
    let mut d = PbDecoder::new(raw);
    let mut out = None;
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => {
                let sb = d.read_bytes()?;
                let mut sd = PbDecoder::new(sb);
                let mut snapshot_id = String::new();
                while let Some((sf, sw)) = sd.next_tag()? {
                    match (sf, sw) {
                        (1, WIRE_LEN) => snapshot_id = sd.read_string()?,
                        _ => sd.skip_field(sw)?,
                    }
                }
                out = Some(VolumeContentSource::Snapshot { snapshot_id });
            }
            (2, WIRE_LEN) => {
                let vb = d.read_bytes()?;
                let mut vd = PbDecoder::new(vb);
                let mut volume_id = String::new();
                while let Some((vf, vw)) = vd.next_tag()? {
                    match (vf, vw) {
                        (1, WIRE_LEN) => volume_id = vd.read_string()?,
                        _ => vd.skip_field(vw)?,
                    }
                }
                out = Some(VolumeContentSource::Volume { volume_id });
            }
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

fn encode_topology(t: &Topology) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_map(1, &t.segments);
    e.into_bytes()
}

fn decode_topology(raw: &[u8]) -> CsiResult<Topology> {
    let mut d = PbDecoder::new(raw);
    let mut out = Topology::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.segments.insert(k, v);
            }
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

fn encode_timestamp(ts: &Timestamp) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_i64(1, ts.seconds);
    e.write_i32(2, ts.nanos);
    e.into_bytes()
}

fn decode_timestamp(raw: &[u8]) -> CsiResult<Timestamp> {
    let mut d = PbDecoder::new(raw);
    let mut out = Timestamp::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_VARINT) => out.seconds = d.read_varint()? as i64,
            (2, WIRE_VARINT) => out.nanos = d.read_varint()? as i32,
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

fn encode_volume(v: &Volume) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_i64(1, v.capacity_bytes);
    e.write_string(2, &v.volume_id);
    e.write_map(3, &v.volume_context);
    if let Some(ref src) = v.content_source {
        e.write_message(4, &encode_content_source(src));
    }
    for topo in &v.accessible_topology {
        e.write_message(5, &encode_topology(topo));
    }
    e.into_bytes()
}

fn decode_volume(raw: &[u8]) -> CsiResult<Volume> {
    let mut d = PbDecoder::new(raw);
    let mut out = Volume::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_VARINT) => out.capacity_bytes = d.read_varint()? as i64,
            (2, WIRE_LEN) => out.volume_id = d.read_string()?,
            (3, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.volume_context.insert(k, v);
            }
            (4, WIRE_LEN) => out.content_source = decode_content_source(d.read_bytes()?)?,
            (5, WIRE_LEN) => out
                .accessible_topology
                .push(decode_topology(d.read_bytes()?)?),
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

fn encode_snapshot(s: &Snapshot) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_i64(1, s.size_bytes);
    e.write_string(2, &s.snapshot_id);
    e.write_string(3, &s.source_volume_id);
    if let Some(ref ts) = s.creation_time {
        e.write_message(4, &encode_timestamp(ts));
    }
    e.write_bool(5, s.ready_to_use);
    e.into_bytes()
}

fn decode_snapshot(raw: &[u8]) -> CsiResult<Snapshot> {
    let mut d = PbDecoder::new(raw);
    let mut out = Snapshot::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_VARINT) => out.size_bytes = d.read_varint()? as i64,
            (2, WIRE_LEN) => out.snapshot_id = d.read_string()?,
            (3, WIRE_LEN) => out.source_volume_id = d.read_string()?,
            (4, WIRE_LEN) => out.creation_time = Some(decode_timestamp(d.read_bytes()?)?),
            (5, WIRE_VARINT) => out.ready_to_use = d.read_varint()? != 0,
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Identity RPC codecs
// ---------------------------------------------------------------------------

pub fn encode_get_plugin_info_resp(r: &GetPluginInfoResponse) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_string(1, &r.name);
    e.write_string(2, &r.vendor_version);
    e.write_map(3, &r.manifest);
    e.into_bytes()
}

pub fn decode_get_plugin_info_resp(raw: &[u8]) -> CsiResult<GetPluginInfoResponse> {
    let mut d = PbDecoder::new(raw);
    let mut out = GetPluginInfoResponse::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => out.name = d.read_string()?,
            (2, WIRE_LEN) => out.vendor_version = d.read_string()?,
            (3, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.manifest.insert(k, v);
            }
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_get_plugin_capabilities_resp(r: &GetPluginCapabilitiesResponse) -> Vec<u8> {
    let mut e = PbEncoder::new();
    for &cap in &r.service_capabilities {
        let mut svc = PbEncoder::new();
        svc.write_u32(1, cap as u32);
        let mut pc = PbEncoder::new();
        pc.write_message(1, &svc.into_bytes());
        e.write_message(1, &pc.into_bytes());
    }
    e.into_bytes()
}

pub fn decode_get_plugin_capabilities_resp(raw: &[u8]) -> CsiResult<GetPluginCapabilitiesResponse> {
    let mut d = PbDecoder::new(raw);
    let mut out = GetPluginCapabilitiesResponse::default();
    while let Some((f, w)) = d.next_tag()? {
        if f == 1 && w == WIRE_LEN {
            let mut pc = PbDecoder::new(d.read_bytes()?);
            while let Some((pf, pw)) = pc.next_tag()? {
                if pf == 1 && pw == WIRE_LEN {
                    let mut svc = PbDecoder::new(pc.read_bytes()?);
                    while let Some((sf, sw)) = svc.next_tag()? {
                        if sf == 1 && sw == WIRE_VARINT {
                            let v = svc.read_varint()? as u32;
                            let cap = match v {
                                1 => PluginServiceCapability::ControllerService,
                                2 => PluginServiceCapability::VolumeAccessibilityConstraints,
                                _ => PluginServiceCapability::Unknown,
                            };
                            out.service_capabilities.push(cap);
                        } else {
                            svc.skip_field(sw)?;
                        }
                    }
                } else {
                    pc.skip_field(pw)?;
                }
            }
        } else {
            d.skip_field(w)?;
        }
    }
    Ok(out)
}

pub fn encode_probe_resp(r: &ProbeResponse) -> Vec<u8> {
    let mut e = PbEncoder::new();
    if let Some(ready) = r.ready {
        let mut bv = PbEncoder::new();
        bv.write_bool_always(1, ready);
        e.write_message(1, &bv.into_bytes());
    }
    e.into_bytes()
}

pub fn decode_probe_resp(raw: &[u8]) -> CsiResult<ProbeResponse> {
    let mut d = PbDecoder::new(raw);
    let mut out = ProbeResponse::default();
    while let Some((f, w)) = d.next_tag()? {
        if f == 1 && w == WIRE_LEN {
            let mut bv = PbDecoder::new(d.read_bytes()?);
            let mut val = false;
            while let Some((bf, bw)) = bv.next_tag()? {
                if bf == 1 && bw == WIRE_VARINT {
                    val = bv.read_varint()? != 0;
                } else {
                    bv.skip_field(bw)?;
                }
            }
            out.ready = Some(val);
        } else {
            d.skip_field(w)?;
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Controller RPC codecs
// ---------------------------------------------------------------------------

pub fn encode_create_volume_req(r: &CreateVolumeRequest) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_string(1, &r.name);
    if let Some(ref cr) = r.capacity_range {
        e.write_message(2, &encode_capacity_range(cr));
    }
    for cap in &r.volume_capabilities {
        e.write_message(3, &encode_volume_capability(cap));
    }
    e.write_map(4, &r.parameters);
    e.write_map(5, &r.secrets);
    if let Some(ref src) = r.volume_content_source {
        e.write_message(6, &encode_content_source(src));
    }
    e.into_bytes()
}

pub fn decode_create_volume_req(raw: &[u8]) -> CsiResult<CreateVolumeRequest> {
    let mut d = PbDecoder::new(raw);
    let mut out = CreateVolumeRequest::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => out.name = d.read_string()?,
            (2, WIRE_LEN) => out.capacity_range = Some(decode_capacity_range(d.read_bytes()?)?),
            (3, WIRE_LEN) => out
                .volume_capabilities
                .push(decode_volume_capability(d.read_bytes()?)?),
            (4, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.parameters.insert(k, v);
            }
            (5, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.secrets.insert(k, v);
            }
            (6, WIRE_LEN) => out.volume_content_source = decode_content_source(d.read_bytes()?)?,
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_create_volume_resp(r: &CreateVolumeResponse) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_message(1, &encode_volume(&r.volume));
    e.into_bytes()
}

pub fn decode_create_volume_resp(raw: &[u8]) -> CsiResult<CreateVolumeResponse> {
    let mut d = PbDecoder::new(raw);
    let mut out = CreateVolumeResponse::default();
    while let Some((f, w)) = d.next_tag()? {
        if f == 1 && w == WIRE_LEN {
            out.volume = decode_volume(d.read_bytes()?)?;
        } else {
            d.skip_field(w)?;
        }
    }
    Ok(out)
}

pub fn encode_delete_volume_req(r: &DeleteVolumeRequest) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_string(1, &r.volume_id);
    e.write_map(2, &r.secrets);
    e.into_bytes()
}

pub fn decode_delete_volume_req(raw: &[u8]) -> CsiResult<DeleteVolumeRequest> {
    let mut d = PbDecoder::new(raw);
    let mut out = DeleteVolumeRequest::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => out.volume_id = d.read_string()?,
            (2, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.secrets.insert(k, v);
            }
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_controller_publish_req(r: &ControllerPublishVolumeRequest) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_string(1, &r.volume_id);
    e.write_string(2, &r.node_id);
    if let Some(ref cap) = r.volume_capability {
        e.write_message(3, &encode_volume_capability(cap));
    }
    e.write_bool(4, r.readonly);
    e.write_map(5, &r.secrets);
    e.write_map(6, &r.volume_context);
    e.into_bytes()
}

pub fn decode_controller_publish_req(raw: &[u8]) -> CsiResult<ControllerPublishVolumeRequest> {
    let mut d = PbDecoder::new(raw);
    let mut out = ControllerPublishVolumeRequest::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => out.volume_id = d.read_string()?,
            (2, WIRE_LEN) => out.node_id = d.read_string()?,
            (3, WIRE_LEN) => {
                out.volume_capability = Some(decode_volume_capability(d.read_bytes()?)?)
            }
            (4, WIRE_VARINT) => out.readonly = d.read_varint()? != 0,
            (5, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.secrets.insert(k, v);
            }
            (6, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.volume_context.insert(k, v);
            }
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_controller_publish_resp(r: &ControllerPublishVolumeResponse) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_map(1, &r.publish_context);
    e.into_bytes()
}

pub fn decode_controller_publish_resp(raw: &[u8]) -> CsiResult<ControllerPublishVolumeResponse> {
    let mut d = PbDecoder::new(raw);
    let mut out = ControllerPublishVolumeResponse::default();
    while let Some((f, w)) = d.next_tag()? {
        if f == 1 && w == WIRE_LEN {
            let (k, v) = d.read_map_entry()?;
            out.publish_context.insert(k, v);
        } else {
            d.skip_field(w)?;
        }
    }
    Ok(out)
}

pub fn encode_controller_unpublish_req(r: &ControllerUnpublishVolumeRequest) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_string(1, &r.volume_id);
    e.write_string(2, &r.node_id);
    e.write_map(3, &r.secrets);
    e.into_bytes()
}

pub fn decode_controller_unpublish_req(raw: &[u8]) -> CsiResult<ControllerUnpublishVolumeRequest> {
    let mut d = PbDecoder::new(raw);
    let mut out = ControllerUnpublishVolumeRequest::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => out.volume_id = d.read_string()?,
            (2, WIRE_LEN) => out.node_id = d.read_string()?,
            (3, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.secrets.insert(k, v);
            }
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_validate_volume_caps_req(r: &ValidateVolumeCapabilitiesRequest) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_string(1, &r.volume_id);
    e.write_map(2, &r.volume_context);
    for cap in &r.volume_capabilities {
        e.write_message(3, &encode_volume_capability(cap));
    }
    e.write_map(4, &r.parameters);
    e.write_map(5, &r.secrets);
    e.into_bytes()
}

pub fn decode_validate_volume_caps_req(raw: &[u8]) -> CsiResult<ValidateVolumeCapabilitiesRequest> {
    let mut d = PbDecoder::new(raw);
    let mut out = ValidateVolumeCapabilitiesRequest::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => out.volume_id = d.read_string()?,
            (2, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.volume_context.insert(k, v);
            }
            (3, WIRE_LEN) => out
                .volume_capabilities
                .push(decode_volume_capability(d.read_bytes()?)?),
            (4, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.parameters.insert(k, v);
            }
            (5, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.secrets.insert(k, v);
            }
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_validate_volume_caps_resp(r: &ValidateVolumeCapabilitiesResponse) -> Vec<u8> {
    let mut e = PbEncoder::new();
    if let Some(ref c) = r.confirmed {
        let mut ce = PbEncoder::new();
        ce.write_map(1, &c.volume_context);
        for cap in &c.volume_capabilities {
            ce.write_message(2, &encode_volume_capability(cap));
        }
        ce.write_map(3, &c.parameters);
        e.write_message(1, &ce.into_bytes());
    }
    e.write_string(2, &r.message);
    e.into_bytes()
}

pub fn decode_validate_volume_caps_resp(
    raw: &[u8],
) -> CsiResult<ValidateVolumeCapabilitiesResponse> {
    let mut d = PbDecoder::new(raw);
    let mut out = ValidateVolumeCapabilitiesResponse::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => {
                let mut cd = PbDecoder::new(d.read_bytes()?);
                let mut conf = ValidateVolumeCapabilitiesConfirmed::default();
                while let Some((cf, cw)) = cd.next_tag()? {
                    match (cf, cw) {
                        (1, WIRE_LEN) => {
                            let (k, v) = cd.read_map_entry()?;
                            conf.volume_context.insert(k, v);
                        }
                        (2, WIRE_LEN) => conf
                            .volume_capabilities
                            .push(decode_volume_capability(cd.read_bytes()?)?),
                        (3, WIRE_LEN) => {
                            let (k, v) = cd.read_map_entry()?;
                            conf.parameters.insert(k, v);
                        }
                        _ => cd.skip_field(cw)?,
                    }
                }
                out.confirmed = Some(conf);
            }
            (2, WIRE_LEN) => out.message = d.read_string()?,
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_list_volumes_req(r: &ListVolumesRequest) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_i32(1, r.max_entries);
    e.write_string(2, &r.starting_token);
    e.into_bytes()
}

pub fn decode_list_volumes_req(raw: &[u8]) -> CsiResult<ListVolumesRequest> {
    let mut d = PbDecoder::new(raw);
    let mut out = ListVolumesRequest::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_VARINT) => out.max_entries = d.read_varint()? as i32,
            (2, WIRE_LEN) => out.starting_token = d.read_string()?,
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_list_volumes_resp(r: &ListVolumesResponse) -> Vec<u8> {
    let mut e = PbEncoder::new();
    for entry in &r.entries {
        let mut ee = PbEncoder::new();
        ee.write_message(1, &encode_volume(&entry.volume));
        if !entry.published_node_ids.is_empty() {
            let mut st = PbEncoder::new();
            for nid in &entry.published_node_ids {
                st.write_string(1, nid);
            }
            ee.write_message(2, &st.into_bytes());
        }
        e.write_message(1, &ee.into_bytes());
    }
    e.write_string(2, &r.next_token);
    e.into_bytes()
}

pub fn decode_list_volumes_resp(raw: &[u8]) -> CsiResult<ListVolumesResponse> {
    let mut d = PbDecoder::new(raw);
    let mut out = ListVolumesResponse::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => {
                let mut ed = PbDecoder::new(d.read_bytes()?);
                let mut entry = ListVolumesEntry::default();
                while let Some((ef, ew)) = ed.next_tag()? {
                    match (ef, ew) {
                        (1, WIRE_LEN) => entry.volume = decode_volume(ed.read_bytes()?)?,
                        (2, WIRE_LEN) => {
                            let mut sd = PbDecoder::new(ed.read_bytes()?);
                            while let Some((sf, sw)) = sd.next_tag()? {
                                if sf == 1 && sw == WIRE_LEN {
                                    entry.published_node_ids.push(sd.read_string()?);
                                } else {
                                    sd.skip_field(sw)?;
                                }
                            }
                        }
                        _ => ed.skip_field(ew)?,
                    }
                }
                out.entries.push(entry);
            }
            (2, WIRE_LEN) => out.next_token = d.read_string()?,
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_controller_get_caps_resp(r: &ControllerGetCapabilitiesResponse) -> Vec<u8> {
    let mut e = PbEncoder::new();
    for &cap in &r.capabilities {
        let mut rpc = PbEncoder::new();
        rpc.write_u32(1, cap as u32);
        let mut item = PbEncoder::new();
        item.write_message(1, &rpc.into_bytes());
        e.write_message(1, &item.into_bytes());
    }
    e.into_bytes()
}

pub fn decode_controller_get_caps_resp(raw: &[u8]) -> CsiResult<ControllerGetCapabilitiesResponse> {
    let mut d = PbDecoder::new(raw);
    let mut out = ControllerGetCapabilitiesResponse::default();
    while let Some((f, w)) = d.next_tag()? {
        if f == 1 && w == WIRE_LEN {
            let mut item = PbDecoder::new(d.read_bytes()?);
            while let Some((itf, itw)) = item.next_tag()? {
                if itf == 1 && itw == WIRE_LEN {
                    let mut rpc = PbDecoder::new(item.read_bytes()?);
                    while let Some((rf, rw)) = rpc.next_tag()? {
                        if rf == 1 && rw == WIRE_VARINT {
                            let v = rpc.read_varint()? as u32;
                            let cap = match v {
                                1 => ControllerRpcCapability::CreateDeleteVolume,
                                2 => ControllerRpcCapability::PublishUnpublishVolume,
                                3 => ControllerRpcCapability::ListVolumes,
                                4 => ControllerRpcCapability::GetCapacity,
                                5 => ControllerRpcCapability::CreateDeleteSnapshot,
                                6 => ControllerRpcCapability::ListSnapshots,
                                7 => ControllerRpcCapability::CloneVolume,
                                8 => ControllerRpcCapability::PublishReadonly,
                                12 => ControllerRpcCapability::SingleNodeMultiWriter,
                                _ => ControllerRpcCapability::Unknown,
                            };
                            out.capabilities.push(cap);
                        } else {
                            rpc.skip_field(rw)?;
                        }
                    }
                } else {
                    item.skip_field(itw)?;
                }
            }
        } else {
            d.skip_field(w)?;
        }
    }
    Ok(out)
}

pub fn encode_create_snapshot_req(r: &CreateSnapshotRequest) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_string(1, &r.source_volume_id);
    e.write_string(2, &r.name);
    e.write_map(3, &r.secrets);
    e.write_map(4, &r.parameters);
    e.into_bytes()
}

pub fn decode_create_snapshot_req(raw: &[u8]) -> CsiResult<CreateSnapshotRequest> {
    let mut d = PbDecoder::new(raw);
    let mut out = CreateSnapshotRequest::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => out.source_volume_id = d.read_string()?,
            (2, WIRE_LEN) => out.name = d.read_string()?,
            (3, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.secrets.insert(k, v);
            }
            (4, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.parameters.insert(k, v);
            }
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_create_snapshot_resp(r: &CreateSnapshotResponse) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_message(1, &encode_snapshot(&r.snapshot));
    e.into_bytes()
}

pub fn decode_create_snapshot_resp(raw: &[u8]) -> CsiResult<CreateSnapshotResponse> {
    let mut d = PbDecoder::new(raw);
    let mut out = CreateSnapshotResponse::default();
    while let Some((f, w)) = d.next_tag()? {
        if f == 1 && w == WIRE_LEN {
            out.snapshot = decode_snapshot(d.read_bytes()?)?;
        } else {
            d.skip_field(w)?;
        }
    }
    Ok(out)
}

pub fn encode_delete_snapshot_req(r: &DeleteSnapshotRequest) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_string(1, &r.snapshot_id);
    e.write_map(2, &r.secrets);
    e.into_bytes()
}

pub fn decode_delete_snapshot_req(raw: &[u8]) -> CsiResult<DeleteSnapshotRequest> {
    let mut d = PbDecoder::new(raw);
    let mut out = DeleteSnapshotRequest::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => out.snapshot_id = d.read_string()?,
            (2, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.secrets.insert(k, v);
            }
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_list_snapshots_req(r: &ListSnapshotsRequest) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_i32(1, r.max_entries);
    e.write_string(2, &r.starting_token);
    e.write_string(3, &r.source_volume_id);
    e.write_string(4, &r.snapshot_id);
    e.into_bytes()
}

pub fn decode_list_snapshots_req(raw: &[u8]) -> CsiResult<ListSnapshotsRequest> {
    let mut d = PbDecoder::new(raw);
    let mut out = ListSnapshotsRequest::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_VARINT) => out.max_entries = d.read_varint()? as i32,
            (2, WIRE_LEN) => out.starting_token = d.read_string()?,
            (3, WIRE_LEN) => out.source_volume_id = d.read_string()?,
            (4, WIRE_LEN) => out.snapshot_id = d.read_string()?,
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_list_snapshots_resp(r: &ListSnapshotsResponse) -> Vec<u8> {
    let mut e = PbEncoder::new();
    for snap in &r.entries {
        let mut ee = PbEncoder::new();
        ee.write_message(1, &encode_snapshot(snap));
        e.write_message(1, &ee.into_bytes());
    }
    e.write_string(2, &r.next_token);
    e.into_bytes()
}

pub fn decode_list_snapshots_resp(raw: &[u8]) -> CsiResult<ListSnapshotsResponse> {
    let mut d = PbDecoder::new(raw);
    let mut out = ListSnapshotsResponse::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => {
                let mut ed = PbDecoder::new(d.read_bytes()?);
                while let Some((ef, ew)) = ed.next_tag()? {
                    if ef == 1 && ew == WIRE_LEN {
                        out.entries.push(decode_snapshot(ed.read_bytes()?)?);
                    } else {
                        ed.skip_field(ew)?;
                    }
                }
            }
            (2, WIRE_LEN) => out.next_token = d.read_string()?,
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Node RPC codecs
// ---------------------------------------------------------------------------

pub fn encode_node_stage_req(r: &NodeStageVolumeRequest) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_string(1, &r.volume_id);
    e.write_map(2, &r.publish_context);
    e.write_string(3, &r.staging_target_path);
    if let Some(ref cap) = r.volume_capability {
        e.write_message(4, &encode_volume_capability(cap));
    }
    e.write_map(5, &r.secrets);
    e.write_map(6, &r.volume_context);
    e.into_bytes()
}

pub fn decode_node_stage_req(raw: &[u8]) -> CsiResult<NodeStageVolumeRequest> {
    let mut d = PbDecoder::new(raw);
    let mut out = NodeStageVolumeRequest::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => out.volume_id = d.read_string()?,
            (2, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.publish_context.insert(k, v);
            }
            (3, WIRE_LEN) => out.staging_target_path = d.read_string()?,
            (4, WIRE_LEN) => {
                out.volume_capability = Some(decode_volume_capability(d.read_bytes()?)?)
            }
            (5, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.secrets.insert(k, v);
            }
            (6, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.volume_context.insert(k, v);
            }
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_node_unstage_req(r: &NodeUnstageVolumeRequest) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_string(1, &r.volume_id);
    e.write_string(2, &r.staging_target_path);
    e.into_bytes()
}

pub fn decode_node_unstage_req(raw: &[u8]) -> CsiResult<NodeUnstageVolumeRequest> {
    let mut d = PbDecoder::new(raw);
    let mut out = NodeUnstageVolumeRequest::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => out.volume_id = d.read_string()?,
            (2, WIRE_LEN) => out.staging_target_path = d.read_string()?,
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_node_publish_req(r: &NodePublishVolumeRequest) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_string(1, &r.volume_id);
    e.write_map(2, &r.publish_context);
    e.write_string(3, &r.staging_target_path);
    e.write_string(4, &r.target_path);
    if let Some(ref cap) = r.volume_capability {
        e.write_message(5, &encode_volume_capability(cap));
    }
    e.write_bool(6, r.readonly);
    e.write_map(7, &r.secrets);
    e.write_map(8, &r.volume_context);
    e.into_bytes()
}

pub fn decode_node_publish_req(raw: &[u8]) -> CsiResult<NodePublishVolumeRequest> {
    let mut d = PbDecoder::new(raw);
    let mut out = NodePublishVolumeRequest::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => out.volume_id = d.read_string()?,
            (2, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.publish_context.insert(k, v);
            }
            (3, WIRE_LEN) => out.staging_target_path = d.read_string()?,
            (4, WIRE_LEN) => out.target_path = d.read_string()?,
            (5, WIRE_LEN) => {
                out.volume_capability = Some(decode_volume_capability(d.read_bytes()?)?)
            }
            (6, WIRE_VARINT) => out.readonly = d.read_varint()? != 0,
            (7, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.secrets.insert(k, v);
            }
            (8, WIRE_LEN) => {
                let (k, v) = d.read_map_entry()?;
                out.volume_context.insert(k, v);
            }
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_node_unpublish_req(r: &NodeUnpublishVolumeRequest) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_string(1, &r.volume_id);
    e.write_string(2, &r.target_path);
    e.into_bytes()
}

pub fn decode_node_unpublish_req(raw: &[u8]) -> CsiResult<NodeUnpublishVolumeRequest> {
    let mut d = PbDecoder::new(raw);
    let mut out = NodeUnpublishVolumeRequest::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => out.volume_id = d.read_string()?,
            (2, WIRE_LEN) => out.target_path = d.read_string()?,
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_node_volume_stats_req(r: &NodeGetVolumeStatsRequest) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_string(1, &r.volume_id);
    e.write_string(2, &r.volume_path);
    e.write_string(3, &r.staging_target_path);
    e.into_bytes()
}

pub fn decode_node_volume_stats_req(raw: &[u8]) -> CsiResult<NodeGetVolumeStatsRequest> {
    let mut d = PbDecoder::new(raw);
    let mut out = NodeGetVolumeStatsRequest::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => out.volume_id = d.read_string()?,
            (2, WIRE_LEN) => out.volume_path = d.read_string()?,
            (3, WIRE_LEN) => out.staging_target_path = d.read_string()?,
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}

pub fn encode_node_volume_stats_resp(r: &NodeGetVolumeStatsResponse) -> Vec<u8> {
    let mut e = PbEncoder::new();
    for u in &r.usage {
        let mut ue = PbEncoder::new();
        ue.write_i64(1, u.available);
        ue.write_i64(2, u.total);
        ue.write_i64(3, u.used);
        ue.write_u32(4, u.unit as u32);
        e.write_message(1, &ue.into_bytes());
    }
    e.into_bytes()
}

pub fn decode_node_volume_stats_resp(raw: &[u8]) -> CsiResult<NodeGetVolumeStatsResponse> {
    let mut d = PbDecoder::new(raw);
    let mut out = NodeGetVolumeStatsResponse::default();
    while let Some((f, w)) = d.next_tag()? {
        if f == 1 && w == WIRE_LEN {
            let mut ud = PbDecoder::new(d.read_bytes()?);
            let mut u = VolumeUsage::default();
            while let Some((uf, uw)) = ud.next_tag()? {
                match (uf, uw) {
                    (1, WIRE_VARINT) => u.available = ud.read_varint()? as i64,
                    (2, WIRE_VARINT) => u.total = ud.read_varint()? as i64,
                    (3, WIRE_VARINT) => u.used = ud.read_varint()? as i64,
                    (4, WIRE_VARINT) => {
                        u.unit = match ud.read_varint()? as u32 {
                            1 => VolumeUsageUnit::Bytes,
                            2 => VolumeUsageUnit::Inodes,
                            _ => VolumeUsageUnit::Unknown,
                        };
                    }
                    _ => ud.skip_field(uw)?,
                }
            }
            out.usage.push(u);
        } else {
            d.skip_field(w)?;
        }
    }
    Ok(out)
}

pub fn encode_node_get_caps_resp(r: &NodeGetCapabilitiesResponse) -> Vec<u8> {
    let mut e = PbEncoder::new();
    for &cap in &r.capabilities {
        let mut rpc = PbEncoder::new();
        rpc.write_u32(1, cap as u32);
        let mut item = PbEncoder::new();
        item.write_message(1, &rpc.into_bytes());
        e.write_message(1, &item.into_bytes());
    }
    e.into_bytes()
}

pub fn decode_node_get_caps_resp(raw: &[u8]) -> CsiResult<NodeGetCapabilitiesResponse> {
    let mut d = PbDecoder::new(raw);
    let mut out = NodeGetCapabilitiesResponse::default();
    while let Some((f, w)) = d.next_tag()? {
        if f == 1 && w == WIRE_LEN {
            let mut item = PbDecoder::new(d.read_bytes()?);
            while let Some((itf, itw)) = item.next_tag()? {
                if itf == 1 && itw == WIRE_LEN {
                    let mut rpc = PbDecoder::new(item.read_bytes()?);
                    while let Some((rf, rw)) = rpc.next_tag()? {
                        if rf == 1 && rw == WIRE_VARINT {
                            let cap = match rpc.read_varint()? as u32 {
                                1 => NodeRpcCapability::StageUnstageVolume,
                                2 => NodeRpcCapability::GetVolumeStats,
                                5 => NodeRpcCapability::SingleNodeMultiWriter,
                                _ => NodeRpcCapability::Unknown,
                            };
                            out.capabilities.push(cap);
                        } else {
                            rpc.skip_field(rw)?;
                        }
                    }
                } else {
                    item.skip_field(itw)?;
                }
            }
        } else {
            d.skip_field(w)?;
        }
    }
    Ok(out)
}

pub fn encode_node_get_info_resp(r: &NodeGetInfoResponse) -> Vec<u8> {
    let mut e = PbEncoder::new();
    e.write_string(1, &r.node_id);
    e.write_i64(2, r.max_volumes_per_node);
    if let Some(ref topo) = r.accessible_topology {
        e.write_message(3, &encode_topology(topo));
    }
    e.into_bytes()
}

pub fn decode_node_get_info_resp(raw: &[u8]) -> CsiResult<NodeGetInfoResponse> {
    let mut d = PbDecoder::new(raw);
    let mut out = NodeGetInfoResponse::default();
    while let Some((f, w)) = d.next_tag()? {
        match (f, w) {
            (1, WIRE_LEN) => out.node_id = d.read_string()?,
            (2, WIRE_VARINT) => out.max_volumes_per_node = d.read_varint()? as i64,
            (3, WIRE_LEN) => out.accessible_topology = Some(decode_topology(d.read_bytes()?)?),
            _ => d.skip_field(w)?,
        }
    }
    Ok(out)
}
