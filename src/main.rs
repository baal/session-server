extern crate time;
extern crate rand;
extern crate libc;

mod cdb;

use std::char;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter, Error as IoError};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::thread;

use rand::Rng;

const SESSION_PERIOD: i64 = 3600;
const FILE_SOCKET: &'static str = "/tmp/login.socket";
const FILE_USERS_CDB: &'static str = "users.cdb";
const FILE_USERS_OLD: &'static str = "users.old";
const FILE_USERS_NEW: &'static str = "users.new";
const FILE_USERS_TMP: &'static str = "users.tmp";

enum SaveError {
	Msg(&'static str),
	Io(IoError),
}

impl From<IoError> for SaveError {
	fn from(e: IoError) -> SaveError {
		SaveError::Io(e)
	}
}

fn bytes_to_string(bytes: &[u8]) -> String {
	let mut ret = String::new();
	for b in bytes.iter() {
		let hi: u8 = *b >> 4 & 15;
		if hi <= 9 {
			ret.push((b'0' + hi) as char);
		} else if 10 <= hi && hi <= 15 {
			ret.push((b'A' + hi - 10) as char);
		}
		let lo: u8 = *b & 15;
		if lo <= 9 {
			ret.push((b'0' + lo) as char);
		} else if 10 <= lo && lo <= 15 {
			ret.push((b'A' + lo - 10) as char);
		}
	}
	ret
}

struct Session {
	user: String,
	last_accessed: i64,
}

impl Session {
	fn new(user: &str) -> Session {
		Session {
			user: user.to_string(),
			last_accessed: time::get_time().sec,
		}
	}
	fn update(&mut self) {
		self.last_accessed = time::get_time().sec;
	}
}

struct SessionManager {
	seqno: u8,
	sessions: HashMap<String, Session>,
	created_users: HashMap<String, String>,
	updated_users: HashMap<String, String>,
	deleted_users: HashMap<String, String>,
}

impl SessionManager {
	fn new() -> SessionManager {
		SessionManager {
			seqno: 0,
			sessions: HashMap::new(),
			created_users: HashMap::new(),
			updated_users: HashMap::new(),
			deleted_users: HashMap::new(),
		}
	}
	fn clean(&mut self) {
		let now = time::get_time().sec;
		let keys: Vec<String> = self.sessions.iter().filter(|&(_, v)| v.last_accessed + SESSION_PERIOD < now).map(|(k, _)| k.clone()).collect();
		for session_id in keys {
			self.sessions.remove(&session_id);
		}
	}
	fn create_session_id(&mut self) -> String {
		let mut bytes: [u8; 16] = [0; 16];
		let mut rng = rand::thread_rng();
		rng.fill_bytes(&mut bytes[..15]);
		self.seqno = if self.seqno == u8::max_value() { 0 } else { self.seqno + 1 };
		bytes[15] = self.seqno;
		bytes_to_string(&bytes)
	}
	fn login(&mut self, user: &str, pass: &str) -> Result<String, &'static str> {
		let result = ! self.deleted_users.contains_key(user) &&
		match self.created_users.get(user) {
			Some(pw) => pw == pass,
			None => match self.updated_users.get(user) {
				Some(pw) => pw == pass,
				None => match cdb::cdb_get(FILE_USERS_CDB, user) {
					Ok(pw) => pw == pass,
					Err(_) => false,
				},
			},
		};
		if result {
			let session_id = self.create_session_id();
			self.sessions.insert(session_id.clone(), Session::new(user));
			Ok(session_id)
		} else {
			Err("Login failed.")
		}
	}
	fn is_logged_in(&mut self, session_id: &str) -> Result<&Session, &'static str> {
		if let Some(session) = self.sessions.get_mut(session_id) {
			if session.last_accessed + SESSION_PERIOD > time::get_time().sec {
				session.update();
				return Ok(session);
			}
		}
		Err("Session not found.")
	}
	fn logout(&mut self, session_id: &str) -> Result<Session, &'static str> {
		self.sessions.remove(session_id).ok_or("Session not found.")
	}
	fn create_user(&mut self, user: &str, pass: &str) -> Result<String, &'static str> {
		let result = if self.deleted_users.contains_key(user) {
			! self.created_users.contains_key(user)
		} else {
			! self.created_users.contains_key(user) &&
			! self.updated_users.contains_key(user) &&
			! cdb::cdb_get(FILE_USERS_CDB, user).is_ok()
		};
		if result {
			self.created_users.insert(user.to_string(), pass.to_string());
			let session_id = self.create_session_id();
			self.sessions.insert(session_id.clone(), Session::new(user));
			Ok(session_id)
		} else {
			Err("User already exists.")
		}
	}
	fn update_user(&mut self, user: &str, pass: &str) -> Result<(), &'static str> {
		if self.created_users.contains_key(user) {
			self.created_users.insert(user.to_string(), pass.to_string());
			Ok(())
		} else if self.deleted_users.contains_key(user) {
			Err("User not found.")
		} else if self.updated_users.contains_key(user) {
			self.updated_users.insert(user.to_string(), pass.to_string());
			Ok(())
		} else if cdb::cdb_get(FILE_USERS_CDB, user).is_ok() {
			self.updated_users.insert(user.to_string(), pass.to_string());
			Ok(())
		} else {
			Err("User not found.")
		}
	}
	fn delete_user(&mut self, user: &str) -> Result<(), &'static str> {
		if self.created_users.contains_key(user) {
			self.created_users.remove(user);
			Ok(())
		} else if self.deleted_users.contains_key(user) {
			Err("User not found.")
		} else if let Some(pw) = self.updated_users.get(user) {
			self.deleted_users.insert(user.to_string(), pw.to_string());
			Ok(())
		} else if let Ok(pw) = cdb::cdb_get(FILE_USERS_CDB, user) {
			self.deleted_users.insert(user.to_string(), pw.to_string());
			Ok(())
		} else {
			Err("User not found.")
		}
	}
	fn save(&mut self) -> Result<(), SaveError> {
		if let Ok(_) = cdb::cdb_export(FILE_USERS_CDB, FILE_USERS_OLD) {
			let of = File::open(FILE_USERS_OLD)?;
			let nf = File::create(FILE_USERS_NEW)?;
			let reader = BufReader::new(of);
			let mut writer = BufWriter::new(nf);
			for line in reader.lines() {
				if let Ok(line) = line {
					if let Some(pos) = line.find(char::is_whitespace) {
						let user = &line[..pos];
						let pass = &line[pos + 1..];
						if ! self.deleted_users.contains_key(user) {
							if let Some(pw) = self.updated_users.get(user) {
								let mut buf = String::from(user);
								buf.push('\x20');
								buf.push_str(pw);
								buf.push('\n');
								writer.write(buf.as_bytes())?;
							} else {
								let mut buf = String::from(user);
								buf.push('\x20');
								buf.push_str(pass);
								buf.push('\n');
								writer.write(buf.as_bytes())?;
							}
						}
					}
				}
			}
			for (user,pass) in self.created_users.iter() {
				let mut buf = String::new();
				buf.push_str(user);
				buf.push('\x20');
				buf.push_str(pass);
				buf.push('\n');
				writer.write(buf.as_bytes())?;
			}
			writer.flush()?;
			if let Ok(_) = cdb::cdb_import(FILE_USERS_TMP, FILE_USERS_NEW) {
				fs::rename(FILE_USERS_TMP, FILE_USERS_CDB)?;
				self.created_users.clear();
				self.updated_users.clear();
				self.deleted_users.clear();
				Ok(())
			} else {
				Err(SaveError::Msg("Import failed."))
			}
		} else {
			Err(SaveError::Msg("Export failed."))
		}
	}
}

fn handler(session_manager: &Arc<Mutex<SessionManager>>, stream: UnixStream) {
	let mut reader = BufReader::new(&stream);
	let mut writer = BufWriter::new(&stream);
	let mut line = String::new();
	if let Ok(_) = reader.read_line(&mut line) {
		let mut sp = line.trim().split_whitespace();
		if let Some(cmd) = sp.next() {
			if cmd == "LOGIN" {
				let user = sp.next().unwrap_or("");
				let pass = sp.next().unwrap_or("");
				if let Ok(mut session_manager) = session_manager.lock() {
					session_manager.clean();
					match session_manager.login(user, pass) {
						Ok(session_id) => {
							writer.write(b"OK ").unwrap();
							writer.write(session_id.as_bytes()).unwrap();
							writer.write(b"\r\n").unwrap();
						},
						Err(error) => {
							writer.write(b"NG ").unwrap();
							writer.write(error.as_bytes()).unwrap();
							writer.write(b"\r\n").unwrap();
						},
					}
				}
			} else if cmd == "SESSION" {
				let session_id = sp.next().unwrap_or("");
				if let Ok(mut session_manager) = session_manager.lock() {
					match session_manager.is_logged_in(session_id) {
						Ok(session) => {
							writer.write(b"OK ").unwrap();
							writer.write(session.user.as_bytes()).unwrap();
							writer.write(b"\r\n").unwrap();
						},
						Err(error) => {
							writer.write(b"NG ").unwrap();
							writer.write(error.as_bytes()).unwrap();
							writer.write(b"\r\n").unwrap();
						},
					}
				}
			} else if cmd == "LOGOUT" {
				let session_id = sp.next().unwrap_or("");
				if let Ok(mut session_manager) = session_manager.lock() {
					match session_manager.logout(session_id) {
						Ok(session) => {
							writer.write(b"OK ").unwrap();
							writer.write(session.user.as_bytes()).unwrap();
							writer.write(b"\r\n").unwrap();
						},
						Err(error) => {
							writer.write(b"NG ").unwrap();
							writer.write(error.as_bytes()).unwrap();
							writer.write(b"\r\n").unwrap();
						},
					}
				}
			} else if cmd == "CREATE" {
				let user = sp.next().unwrap_or("");
				let pass = sp.next().unwrap_or("");
				if let Ok(mut session_manager) = session_manager.lock() {
					match session_manager.create_user(user, pass) {
						Ok(session_id) => {
							writer.write(b"OK ").unwrap();
							writer.write(session_id.as_bytes()).unwrap();
							writer.write(b"\r\n").unwrap();
						},
						Err(error) => {
							writer.write(b"NG ").unwrap();
							writer.write(error.as_bytes()).unwrap();
							writer.write(b"\r\n").unwrap();
						},
					}
				}
			} else if cmd == "UPDATE" {
				let user = sp.next().unwrap_or("");
				let pass = sp.next().unwrap_or("");
				if let Ok(mut session_manager) = session_manager.lock() {
					match session_manager.update_user(user, pass) {
						Ok(_) => {
							writer.write(b"OK\r\n").unwrap();
						},
						Err(error) => {
							writer.write(b"NG ").unwrap();
							writer.write(error.as_bytes()).unwrap();
							writer.write(b"\r\n").unwrap();
						},
					}
				}
			} else if cmd == "DELETE" {
				let user = sp.next().unwrap_or("");
				if let Ok(mut session_manager) = session_manager.lock() {
					match session_manager.delete_user(user) {
						Ok(_) => {
							writer.write(b"OK\r\n").unwrap();
						},
						Err(error) => {
							writer.write(b"NG ").unwrap();
							writer.write(error.as_bytes()).unwrap();
							writer.write(b"\r\n").unwrap();
						},
					}
				}
			} else if cmd == "SAVE" {
				if let Ok(mut session_manager) = session_manager.lock() {
					match session_manager.save() {
						Ok(_) => {
							writer.write(b"OK\r\n").unwrap();
						},
						Err(error) => {
							match error {
								SaveError::Io(e) => {
									writer.write(b"NG ").unwrap();
									writer.write(e.description().as_bytes()).unwrap();
									writer.write(b"\r\n").unwrap();
								},
								SaveError::Msg(m) => {
									writer.write(b"NG ").unwrap();
									writer.write(m.as_bytes()).unwrap();
									writer.write(b"\r\n").unwrap();
								},
							}
						},
					}
				}
			} else {
				writer.write(b"ERROR\r\n").unwrap();
			}
		}
	}
}

fn main() {
	let session_manager = Arc::new(Mutex::new(SessionManager::new()));
	let listener = UnixListener::bind(FILE_SOCKET).unwrap();
	for stream in listener.incoming() {
		if let Ok(stream) = stream {
			let session_manager = session_manager.clone();
			thread::spawn(move || handler(&session_manager, stream));
		}
	}
}
