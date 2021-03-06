extern crate time;
extern crate rand;
extern crate libc;

mod cdb;

use std::char;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs::File;
use std::fs;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter, Error as IoError};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rand::Rng;

const LOCK_COUNT: u64 = 5;
const SESSION_PERIOD: i64 = 3600;
const FILE_SOCKET: &'static str = "sessiond.sock";
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

struct User {
	name: String,
	password: String,
	created: i64,
	updated: i64,
	deleted: i64,
	last_loggedin: i64,
	failed: i64,
	fail_count: u64,
	locked: i64,
}

impl User {
	fn new(name: &str, password: &str) -> User {
		User {
			name: name.to_string(),
			password: password.to_string(),
			created: time::get_time().sec,
			updated: 0,
			deleted: 0,
			last_loggedin: 0,
			failed: 0,
			fail_count: 0,
			locked: 0,
		}
	}
	fn parse(name: &str, rest: &str) -> User {
		let mut parts = rest.split_whitespace();
		User {
			name: name.to_string(),
			password: parts.next().map_or(String::new(), |s| String::from(s)),
			created: parts.next().map_or(0, |s| i64::from_str_radix(s, 10).unwrap_or(0)),
			updated: parts.next().map_or(0, |s| i64::from_str_radix(s, 10).unwrap_or(0)),
			deleted: parts.next().map_or(0, |s| i64::from_str_radix(s, 10).unwrap_or(0)),
			last_loggedin: parts.next().map_or(0, |s| i64::from_str_radix(s, 10).unwrap_or(0)),
			failed: parts.next().map_or(0, |s| i64::from_str_radix(s, 10).unwrap_or(0)),
			fail_count: parts.next().map_or(0, |s| u64::from_str_radix(s, 10).unwrap_or(0)),
			locked: parts.next().map_or(0, |s| i64::from_str_radix(s, 10).unwrap_or(0)),
		}
	}
	fn to_string(&self) -> String {
		let mut buf = String::new();
		buf.push_str(self.name.as_str());
		buf.push('\x20');
		buf.push_str(self.password.as_str());
		buf.push('\x20');
		buf.push_str(self.created.to_string().as_str());
		buf.push('\x20');
		buf.push_str(self.updated.to_string().as_str());
		buf.push('\x20');
		buf.push_str(self.deleted.to_string().as_str());
		buf.push('\x20');
		buf.push_str(self.last_loggedin.to_string().as_str());
		buf.push('\x20');
		buf.push_str(self.failed.to_string().as_str());
		buf.push('\x20');
		buf.push_str(self.fail_count.to_string().as_str());
		buf.push('\x20');
		buf.push_str(self.locked.to_string().as_str());
		buf
	}
	fn is_deleted(&self) -> bool {
		self.deleted != 0
	}
	fn is_locked(&self) -> bool {
		self.locked != 0
	}
}

struct Session {
	name: String,
	last_accessed: i64,
}

impl Session {
	fn new(name: &str) -> Session {
		Session {
			name: name.to_string(),
			last_accessed: time::get_time().sec,
		}
	}
	fn update(&mut self) {
		self.last_accessed = time::get_time().sec;
	}
}

struct SessionManager {
	seqno: u8,
	dir: String,
	path_users_cdb: String,
	sessions: HashMap<String, Session>,
	created_users: HashMap<String, User>,
	updated_users: HashMap<String, User>,
}

impl SessionManager {
	fn new(dir: String) -> SessionManager {
		let path = if dir.len() != 0 {
				let mut path_buf = PathBuf::from(dir.clone());
				path_buf.push(FILE_USERS_CDB);
				path_buf.as_path().to_str().unwrap_or(FILE_USERS_CDB).to_string()
			} else {
				String::from(FILE_USERS_CDB)
			};
		SessionManager {
			seqno: 0,
			dir: dir,
			path_users_cdb: path,
			sessions: HashMap::new(),
			created_users: HashMap::new(),
			updated_users: HashMap::new(),
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
	fn auth(&mut self, name: &str, pass: &str) -> Result<(), &'static str> {
		let mut result = false;
		if self.created_users.contains_key(name) {
			if let Some(user) = self.created_users.get_mut(name) {
				if ! user.is_locked() {
					if user.password == pass {
						user.fail_count = 0;
						result = true;
					} else {
						user.failed = time::get_time().sec;
						user.fail_count += 1;
						if user.fail_count >= LOCK_COUNT {
							user.locked = user.failed;
						}
					}
				}
			}
		} else if self.updated_users.contains_key(name) {
			if let Some(user) = self.updated_users.get_mut(name) {
				if ! user.is_locked() && ! user.is_deleted() {
					if user.password == pass {
						user.fail_count = 0;
						result = true;
					} else {
						user.failed = time::get_time().sec;
						user.fail_count += 1;
						if user.fail_count >= LOCK_COUNT {
							user.locked = user.failed;
						}
					}
				}
			}
		} else if let Ok(s) = cdb::cdb_get(self.path_users_cdb.as_str(), name) {
			let mut user = User::parse(name, s.as_str());
			if ! user.is_locked() && ! user.is_deleted() {
				if user.password == pass {
					user.fail_count = 0;
					result = true;
				} else {
					user.failed = time::get_time().sec;
					user.fail_count += 1;
					if user.fail_count >= LOCK_COUNT {
						user.locked = user.failed;
					}
				}
			}
			self.updated_users.insert(name.to_string(), user);
		}
		if result {
			Ok(())
		} else {
			Err("Authentication failed.")
		}
	}
	fn login(&mut self, name: &str, pass: &str) -> Result<String, &'static str> {
		let mut result = false;
		if self.created_users.contains_key(name) {
			if let Some(user) = self.created_users.get_mut(name) {
				if ! user.is_locked() {
					if user.password == pass {
						user.fail_count = 0;
						user.last_loggedin = time::get_time().sec;
						result = true;
					} else {
						user.failed = time::get_time().sec;
						user.fail_count += 1;
						if user.fail_count >= LOCK_COUNT {
							user.locked = user.failed;
						}
					}
				}
			}
		} else if self.updated_users.contains_key(name) {
			if let Some(user) = self.updated_users.get_mut(name) {
				if ! user.is_locked() && ! user.is_deleted() {
					if user.password == pass {
						user.fail_count = 0;
						user.last_loggedin = time::get_time().sec;
						result = true;
					} else {
						user.failed = time::get_time().sec;
						user.fail_count += 1;
						if user.fail_count >= LOCK_COUNT {
							user.locked = user.failed;
						}
					}
				}
			}
		} else if let Ok(s) = cdb::cdb_get(self.path_users_cdb.as_str(), name) {
			let mut user = User::parse(name, s.as_str());
			if ! user.is_locked() && ! user.is_deleted() {
				if user.password == pass {
					user.fail_count = 0;
					user.last_loggedin = time::get_time().sec;
					result = true;
				} else {
					user.failed = time::get_time().sec;
					user.fail_count += 1;
					if user.fail_count >= LOCK_COUNT {
						user.locked = user.failed;
					}
				}
			}
			self.updated_users.insert(name.to_string(), user);
		}
		if result {
			let session_id = self.create_session_id();
			self.sessions.insert(session_id.clone(), Session::new(name));
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
	fn create_user(&mut self, name: &str, pass: &str) -> Result<String, &'static str> {
		if
			! self.created_users.contains_key(name) &&
			! self.updated_users.contains_key(name) &&
			! cdb::cdb_get(self.path_users_cdb.as_str(), name).is_ok()
		{
			self.created_users.insert(name.to_string(), User::new(name, pass));
			let session_id = self.create_session_id();
			self.sessions.insert(session_id.clone(), Session::new(name));
			Ok(session_id)
		} else {
			Err("User already exists.")
		}
	}
	fn update_user(&mut self, name: &str, pass: &str) -> Result<(), &'static str> {
		if let Some(user) = self.created_users.get_mut(name) {
			user.password = pass.to_string();
			user.updated = time::get_time().sec;
			return Ok(());
		}
		if self.updated_users.contains_key(name) {
			if let Some(user) = self.updated_users.get_mut(name) {
				if ! user.is_deleted() {
					user.password = pass.to_string();
					user.updated = time::get_time().sec;
					return Ok(());
				}
			}
		} else if let Ok(s) = cdb::cdb_get(self.path_users_cdb.as_str(), name) {
			let mut user = User::parse(name, s.as_str());
			if ! user.is_deleted() {
				user.password = pass.to_string();
				user.updated = time::get_time().sec;
				self.updated_users.insert(name.to_string(), user);
				return Ok(());
			}
		}
		Err("User not found.")
	}
	fn delete_user(&mut self, name: &str) -> Result<(), &'static str> {
		if self.created_users.contains_key(name) {
			self.created_users.remove(name);
			return Ok(());
		}
		if self.updated_users.contains_key(name) {
			if let Some(user) = self.updated_users.get_mut(name) {
				if ! user.is_deleted() {
					user.deleted = time::get_time().sec;
					return Ok(());
				}
			}
		} else if let Ok(s) = cdb::cdb_get(self.path_users_cdb.as_str(), name) {
			let mut user = User::parse(name, s.as_str());
			if ! user.is_deleted() {
				user.deleted = time::get_time().sec;
				self.updated_users.insert(name.to_string(), user);
				return Ok(());
			}
		}
		Err("User not found.")
	}
	fn save(&mut self) -> Result<(), SaveError> {
		let path_users_old = if self.dir.len() != 0 {
				let mut path_buf = PathBuf::from(self.dir.clone());
				path_buf.push(FILE_USERS_OLD);
				path_buf.as_path().to_str().unwrap_or(FILE_USERS_OLD).to_string()
			} else {
				String::from(FILE_USERS_OLD)
			};
		let path_users_new = if self.dir.len() != 0 {
				let mut path_buf = PathBuf::from(self.dir.clone());
				path_buf.push(FILE_USERS_NEW);
				path_buf.as_path().to_str().unwrap_or(FILE_USERS_NEW).to_string()
			} else {
				String::from(FILE_USERS_NEW)
			};
		let path_users_tmp = if self.dir.len() != 0 {
				let mut path_buf = PathBuf::from(self.dir.clone());
				path_buf.push(FILE_USERS_TMP);
				path_buf.as_path().to_str().unwrap_or(FILE_USERS_TMP).to_string()
			} else {
				String::from(FILE_USERS_TMP)
			};
		if let Ok(_) = cdb::cdb_export(self.path_users_cdb.as_str(), path_users_old.as_str()) {
			let of = File::open(path_users_old.as_str())?;
			let nf = File::create(path_users_new.as_str())?;
			let reader = BufReader::new(of);
			let mut writer = BufWriter::new(nf);
			for line in reader.lines() {
				if let Ok(line) = line {
					if let Some(pos) = line.find(char::is_whitespace) {
						let name = &line[..pos];
						if let Some(user) = self.updated_users.get(name) {
							let mut buf = String::from(user.to_string());
							buf.push('\n');
							writer.write(buf.as_bytes())?;
						} else {
							let mut buf = String::from(line.as_str());
							buf.push('\n');
							writer.write(buf.as_bytes())?;
						}
					}
				}
			}
			for (_, user) in self.created_users.iter() {
				let mut buf = String::from(user.to_string());
				buf.push('\n');
				writer.write(buf.as_bytes())?;
			}
			writer.flush()?;
			if let Ok(_) = cdb::cdb_import(path_users_tmp.as_str(), path_users_new.as_str()) {
				fs::rename(path_users_tmp.as_str(), self.path_users_cdb.as_str())?;
				self.created_users.clear();
				self.updated_users.clear();
				Ok(())
			} else {
				Err(SaveError::Msg("Import failed."))
			}
		} else {
			Err(SaveError::Msg("Export failed."))
		}
	}
}

fn handler(session_manager: Arc<Mutex<SessionManager>>, stream: UnixStream) {
	let mut reader = BufReader::new(&stream);
	let mut writer = BufWriter::new(&stream);
	let mut line = String::new();
	if let Ok(_) = reader.read_line(&mut line) {
		let mut sp = line.trim().split_whitespace();
		if let Some(cmd) = sp.next() {
			if cmd == "AUTH" {
				let name = sp.next().unwrap_or("");
				let pass = sp.next().unwrap_or("");
				if let Ok(mut session_manager) = session_manager.lock() {
					match session_manager.auth(name, pass) {
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
			} else if cmd == "LOGIN" {
				let name = sp.next().unwrap_or("");
				let pass = sp.next().unwrap_or("");
				if let Ok(mut session_manager) = session_manager.lock() {
					match session_manager.login(name, pass) {
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
							writer.write(session.name.as_bytes()).unwrap();
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
							writer.write(session.name.as_bytes()).unwrap();
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
				let name = sp.next().unwrap_or("");
				let pass = sp.next().unwrap_or("");
				if let Ok(mut session_manager) = session_manager.lock() {
					match session_manager.create_user(name, pass) {
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
				let name = sp.next().unwrap_or("");
				let pass = sp.next().unwrap_or("");
				if let Ok(mut session_manager) = session_manager.lock() {
					match session_manager.update_user(name, pass) {
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
				let name = sp.next().unwrap_or("");
				if let Ok(mut session_manager) = session_manager.lock() {
					match session_manager.delete_user(name) {
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

fn maintenance(session_manager: Arc<Mutex<SessionManager>>) {
	loop {
		if let Ok(mut session_manager) = session_manager.lock() {
			session_manager.clean();
			if
				! session_manager.created_users.is_empty() ||
				! session_manager.updated_users.is_empty()
			{
				let _ = session_manager.save();
			}
		}
		thread::sleep(Duration::from_secs(600));
	}
}

fn get_args() -> (String, String) {
	let mut path_sock = String::new();
	let mut dir_user = String::new();
	let mut flag_path_sock = false;
	let mut flag_dir_user = false;
	for arg in env::args() {
		if flag_path_sock {
			path_sock = arg;
			flag_path_sock = false;
			continue;
		}
		if flag_dir_user {
			dir_user = arg;
			flag_dir_user = false;
			continue;
		}
		if arg == "-sock" {
			flag_path_sock = true;
			continue;
		}
		if arg == "-dir" {
			flag_dir_user = true;
			continue;
		}
	}
	return (path_sock, dir_user);
}

fn main() {
	let (path, dir) = get_args();

	let session_manager = Arc::new(Mutex::new(SessionManager::new(dir)));

	let sm = session_manager.clone();
	thread::spawn(move || maintenance(sm));

	let listener = UnixListener::bind(if path.len() != 0 { path.as_str() } else { FILE_SOCKET }).unwrap();
	for stream in listener.incoming() {
		if let Ok(stream) = stream {
			let sm = session_manager.clone();
			thread::spawn(move || handler(sm, stream));
		}
	}
}
