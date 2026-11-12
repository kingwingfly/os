//! Stateless byte devices. Authorization belongs to open/pread/pwrite; these
//! drivers never create files, R2 objects or an application-controlled RNG seed.
use abi::{Errno, Error, INLINE_MAX};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(inline_js = "
export function deviceRandom(length) {
  const bytes = new Uint8Array(length);
  for (let at = 0; at < length; at += 65536) crypto.getRandomValues(bytes.subarray(at, at + 65536));
  return bytes;
}
")]
extern "C" {
    #[wasm_bindgen(catch, js_name = deviceRandom)]
    fn random(length: u32) -> Result<js_sys::Uint8Array, JsValue>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteDevice {
    Null,
    Zero,
    Full,
    Random,
    Urandom,
}

impl ByteDevice {
    pub fn named(name: &str) -> Option<Self> {
        Some(match name {
            "null" => Self::Null,
            "zero" => Self::Zero,
            "full" => Self::Full,
            "random" => Self::Random,
            "urandom" => Self::Urandom,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Zero => "zero",
            Self::Full => "full",
            Self::Random => "random",
            Self::Urandom => "urandom",
        }
    }

    pub fn read(self, count: u64) -> Result<Vec<u8>, Error> {
        if count > INLINE_MAX {
            return Err(Errno::E2BIG.into());
        }
        match self {
            Self::Null => Ok(Vec::new()),
            Self::Zero | Self::Full => Ok(vec![0; count as usize]),
            Self::Random | Self::Urandom if count == 0 => Ok(Vec::new()),
            Self::Random | Self::Urandom => random(count as u32)
                .map(|bytes| bytes.to_vec())
                .map_err(|_| Errno::EIO.into()),
        }
    }

    pub fn write(self) -> Result<(), Error> {
        if self == Self::Full {
            Err(Errno::ENOSPC.into())
        } else {
            // Web Crypto owns entropy initialization. Writes are accepted and
            // discarded; they cannot seed or credit a Linux-style entropy pool.
            Ok(())
        }
    }
}
