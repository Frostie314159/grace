use scroll::{
    ctx::{MeasureWith, TryFromCtx, TryIntoCtx},
    Endian, Pread, Pwrite,
};

use crate::util::APPLE_OUI;

pub const AWDL_PID: u16 = 0x0800;

pub struct AWDLLLCFrame<P> {
    pub dsap: u8,
    pub ssap: u8,
    pub payload: P,
}
impl<P: MeasureWith<()>> MeasureWith<()> for AWDLLLCFrame<P> {
    fn measure_with(&self, ctx: &()) -> usize {
        8 + self.payload.measure_with(ctx)
    }
}
impl<'a> TryFromCtx<'a> for AWDLLLCFrame<&'a [u8]> {
    type Error = scroll::Error;
    fn try_from_ctx(from: &'a [u8], _ctx: ()) -> Result<(Self, usize), Self::Error> {
        let mut offset = 0;

        let dsap = from.gread(&mut offset)?;
        let ssap = from.gread(&mut offset)?;
        let control = from.gread::<u8>(&mut offset)?;
        if control != 0x3 {
            return Err(scroll::Error::BadInput {
                size: offset,
                msg: "Control field wasn't set to 0x3.",
            });
        }
        let oui = from.gread::<[u8; 3]>(&mut offset)?;
        if oui != APPLE_OUI {
            return Err(scroll::Error::BadInput {
                size: offset,
                msg: "OUI wasn't set to 00:17:f2.",
            });
        }
        let pid = from.gread_with::<u16>(&mut offset, Endian::Big)?;
        if pid != AWDL_PID {
            return Err(scroll::Error::BadInput {
                size: offset,
                msg: "PID wasn't set to 0x8000.",
            });
        }
        let payload = &from[offset..];
        Ok((
            Self {
                dsap,
                ssap,
                payload,
            },
            offset,
        ))
    }
}
impl<P: TryIntoCtx<Error = scroll::Error>> TryIntoCtx for AWDLLLCFrame<P> {
    type Error = scroll::Error;
    fn try_into_ctx(self, buf: &mut [u8], _ctx: ()) -> Result<usize, Self::Error> {
        let mut offset = 0;

        buf.gwrite(self.dsap, &mut offset)?;
        buf.gwrite(self.ssap, &mut offset)?;
        buf.gwrite(0x3u8, &mut offset)?;
        buf.gwrite(APPLE_OUI, &mut offset)?;
        buf.gwrite_with(AWDL_PID, &mut offset, Endian::Big)?;
        buf.gwrite(self.payload, &mut offset)?;

        Ok(offset)
    }
}
