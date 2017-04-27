use std::ffi::{CString, NulError};
use std::fs::File;
use std::io::{BufReader, SeekFrom, Error as IoError};
use std::io::prelude::*;

use libc::{c_void, c_char, c_uchar, c_int, c_uint, open, close, O_RDONLY, O_RDWR, O_CREAT};

pub enum CDBError {
	Msg(&'static str),
	Io(IoError),
	Nul(NulError),
}

impl From<IoError> for CDBError {
	fn from(e: IoError) -> CDBError {
		CDBError::Io(e)
	}
}

impl From<NulError> for CDBError {
	fn from(e: NulError) -> CDBError {
		CDBError::Nul(e)
	}
}

#[repr(C)]
struct CDB {
	cdb_fd: c_int,
	cdb_fsize: c_uint,
	cdb_dend: c_uint,
	cdb_mem: *mut c_uchar,
	cdb_vpos: c_uint,
	cdb_vlen: c_uint,
	cdb_kpos: c_uint,
	cdb_klen: c_uint,
}

#[repr(C)]
struct CDB_make {
	cdb_fd: c_int,
	cdb_dpos: c_uint,
	cdb_rcnt: c_uint,
	cdb_buf: [c_uchar; 4096],
	cdb_bpos: *mut c_uchar,
	cdb_rec: *mut c_void,
}

#[link(name="cdb")]
extern {
	fn cdb_init(cdb: *mut CDB, fd: c_int) -> c_int;
	fn cdb_find(cdb: *mut CDB, key: *const c_char, klen: c_uint) -> c_int;
	fn cdb_read(cdb: *const CDB, buf: *mut c_void, len: c_uint, pos: c_uint) -> c_int;
	fn cdb_free(cdb: *mut CDB);
	fn cdb_unpack(buf: *const c_uchar) -> c_uint;
	fn cdb_make_start(cdb_make: *mut CDB_make, fd: c_int);
	fn cdb_make_add(cdb_make: *mut CDB_make, key: *const c_void, klen: c_uint, val: *const c_void, vlen: c_uint);
	fn cdb_make_finish(cdb_make: *mut CDB_make);
}

pub fn cdb_get(path: &str, key: &str) -> Result<String, CDBError> {
	unsafe {
		let mut result: Option<String> = None;
		let mut cdb = CDB {
			cdb_fd: 0,
			cdb_fsize: 0,
			cdb_dend: 0,
			cdb_mem: 0 as *mut c_uchar,
			cdb_vpos: 0,
			cdb_vlen: 0,
			cdb_kpos: 0,
			cdb_klen: 0,
		};
		let cpath = CString::new(path)?;
		let ckey = CString::new(key)?;
		let fd = open(cpath.as_ptr(), O_RDONLY);
		cdb_init(&mut cdb, fd);
		if cdb_find(&mut cdb, ckey.as_ptr(), key.len() as c_uint) > 0 {
			let mut buf: Vec<u8> = Vec::with_capacity(cdb.cdb_vlen as usize);
			if cdb_read(&cdb, buf.as_mut_ptr() as *mut c_void, cdb.cdb_vlen, cdb.cdb_vpos) == 0 {
				buf.set_len(cdb.cdb_vlen as usize);
				if let Ok(val) = String::from_utf8(buf) {
					result = Some(val);
				}
			}
		}
		cdb_free(&mut cdb);
		close(fd);
		result.ok_or(CDBError::Msg("CDB Failed."))
	}
}

pub fn cdb_export(cdb_path: &str, out_path: &str) -> Result<(), CDBError> {
	unsafe {
		let mut buf: [u8; 2048] = [0; 2048];
		let mut fin = File::open(cdb_path)?;
		let mut fout = File::create(out_path)?;
		let mut pos: usize = 2048;
		fin.read(&mut buf[..4])?;
		let eod: usize = cdb_unpack(buf[..4].as_mut_ptr()) as usize;
		fin.seek(SeekFrom::Start(pos as u64))?;
		while pos < eod {
			fin.read(&mut buf[..4])?;
			pos += 4;
			let klen = cdb_unpack(buf[..4].as_mut_ptr()) as usize;
			fin.read(&mut buf[..4])?;
			pos += 4;
			let vlen = cdb_unpack(buf[..4].as_mut_ptr()) as usize;
			if klen <= 2048 {
				fin.read(&mut buf[..klen])?;
				fout.write(&buf[..klen])?;
				pos += klen;
			}
			fout.write(b"\x20")?;
			if vlen <= 2048 {
				fin.read(&mut buf[..vlen])?;
				fout.write(&buf[..vlen])?;
				pos += vlen;
			}
			fout.write(b"\n")?;
		}
		Ok(())
	}
}

pub fn cdb_import(cdb_path: &str, in_path: &str) -> Result<(), CDBError> {
	unsafe {
		let mut cdb_make = CDB_make {
			cdb_fd: 0,
			cdb_dpos: 0,
			cdb_rcnt: 0,
			cdb_buf: [0; 4096],
			cdb_bpos: 0 as *mut c_uchar,
			cdb_rec: 0 as *mut c_void,
		};
		let cpath = CString::new(cdb_path)?;
		let fd = open(cpath.as_ptr(), O_RDWR | O_CREAT, 0o660);
		cdb_make_start(&mut cdb_make, fd);
		let fin = File::open(in_path)?;
		let reader = BufReader::new(fin);
		for line in reader.lines() {
			if let Ok(line) = line {
				if let Some(pos) = line.find(char::is_whitespace) {
					let key = &line[..pos];
					let val = &line[pos + 1..];
					let ckey = CString::new(key)?;
					let cval = CString::new(val)?;
					cdb_make_add(&mut cdb_make, ckey.as_ptr() as *const c_void, key.len() as u32, cval.as_ptr() as *const c_void, val.len() as u32);
				}
			}
		}
		cdb_make_finish(&mut cdb_make);
		close(fd);
		Ok(())
	}
}
