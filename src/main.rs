use aes::Aes128;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use cbc::Encryptor;
use inquire::{Confirm, Select, Text};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Error, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::Path;

const DSR_KEY: [u8; 16] = [
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];

#[derive(Debug, Clone)]
enum SoulState {
	Hollow = 8,
	Human = 0,
	Unknown = 4,
}

#[derive(Debug, Clone)]
struct CharacterStats {
	health_current: u32,
	health_max1: u32,
	health_max2: u32,
	stamina2: u32,
	stamina3: u64,
	vitality: u64,
	attunement: u64,
	endurance: u64,
	strength: u64,
	dexterity: u64,
	intelligence: u64,
	faith: u64,
	humanity: u64,
	resistance: u64,
	level: u32,
	souls: u32,
	earned_souls: u64,
	soul_state: SoulState,
	name: String,
	is_male: bool,
	character_class: u8,
	body_type: u8,
	starting_gift: u8,
	poison_resistance: u8,
	bleeding_resistance: u8,
	poison_resistance2: u8,
	damnation_resistance: u8,
	face: u8,
	hair: u8,
	hair_color: u8,
	deaths: u32,
}

impl CharacterStats {
	fn deserialize(file_path: &str) -> Result<Self, Error> {
		let mut file = File::open(file_path)?;
		file.seek(SeekFrom::Start(116))?;

		Ok(CharacterStats {
			health_current: file.read_u32::<LittleEndian>()?,
			health_max1: file.read_u32::<LittleEndian>()?,
			health_max2: file.read_u32::<LittleEndian>()?,

			stamina2: {
				file.seek(SeekFrom::Current(20))?;
				file.read_u32::<LittleEndian>()?
			},
			stamina3: file.read_u64::<LittleEndian>()?,

			vitality: { file.read_u64::<LittleEndian>()? },
			attunement: file.read_u64::<LittleEndian>()?,
			endurance: file.read_u64::<LittleEndian>()?,
			strength: file.read_u64::<LittleEndian>()?,
			dexterity: file.read_u64::<LittleEndian>()?,
			intelligence: file.read_u64::<LittleEndian>()?,
			faith: file.read_u64::<LittleEndian>()?,
			humanity: {
				file.seek(SeekFrom::Current(8))?;
				file.read_u64::<LittleEndian>()?
			},
			resistance: file.read_u64::<LittleEndian>()?,

			level: file.read_u32::<LittleEndian>()?,
			souls: file.read_u32::<LittleEndian>()?,
			earned_souls: file.read_u64::<LittleEndian>()?,

			soul_state: match {
				file.seek(SeekFrom::Current(4))?;
				file.read_u32::<LittleEndian>()?
			} {
				0 => SoulState::Human,
				8 => SoulState::Hollow,
				_ => SoulState::Unknown,
			},

			name: {
				let mut name_bytes = [0u16; 14];
				let mut raw_bytes = [0u8; 28];
				file.read_exact(&mut raw_bytes)?;

				for i in 0..14 {
					name_bytes[i] = u16::from_le_bytes([raw_bytes[i * 2], raw_bytes[i * 2 + 1]]);
				}

				let name_length = name_bytes.iter().position(|&x| x == 0).unwrap_or(name_bytes.len());

				String::from_utf16(&name_bytes[0..name_length])
					.unwrap_or_default()
					.to_string()
			},
			is_male: {
				file.seek(SeekFrom::Current(9))?;
				file.read_u8()? == 1
			},
			character_class: file.read_u8()?,
			body_type: file.read_u8()?,
			starting_gift: file.read_u8()?,

			poison_resistance: {
				file.seek(SeekFrom::Current(63))?;
				file.read_u8()?
			},
			bleeding_resistance: file.read_u8()?,
			poison_resistance2: file.read_u8()?,
			damnation_resistance: file.read_u8()?,

			face: file.read_u8()?,
			hair: file.read_u8()?,
			hair_color: file.read_u8()?,

			deaths: {
				file.seek(SeekFrom::Start(127_448))?;
				file.read_u32::<LittleEndian>()?
			},
		})
	}

	pub fn serialize(&self, file_path: &str) -> Result<(), Error> {
		let mut file = OpenOptions::new()
			.read(true)
			.write(true)
			.open(file_path)
			.map_err(|e| Error::new(ErrorKind::Other, format!("Could not open file: {}", e)))?;

		file.seek(SeekFrom::Start(116))?;

		file.write_u32::<LittleEndian>(self.health_current)?;
		file.write_u32::<LittleEndian>(self.health_max1)?;
		file.write_u32::<LittleEndian>(self.health_max2)?;

		file.seek(SeekFrom::Current(20))?;
		file.write_u32::<LittleEndian>(self.stamina2)?;
		file.write_u64::<LittleEndian>(self.stamina3)?;

		let stats = [
			self.vitality,
			self.attunement,
			self.endurance,
			self.strength,
			self.dexterity,
			self.intelligence,
			self.faith,
			self.humanity,
			self.resistance,
		];

		for stat in stats.iter() {
			file.write_u64::<LittleEndian>(*stat)?;
		}

		file.write_u32::<LittleEndian>(self.level)?;
		file.write_u32::<LittleEndian>(self.souls)?;
		file.write_u64::<LittleEndian>(self.earned_souls)?;

		file.seek(SeekFrom::Current(4))?;
		let soul_state_value = match self.soul_state {
			SoulState::Human => 0,
			SoulState::Hollow => 8,
			SoulState::Unknown => 4,
		};
		file.write_u32::<LittleEndian>(soul_state_value)?;

		let mut name_bytes = [0u16; 14];
		let name_utf16: Vec<u16> = self.name.encode_utf16().collect();
		let name_len = name_utf16.len().min(14);
		name_bytes[..name_len].copy_from_slice(&name_utf16[..name_len]);

		let mut raw_bytes = [0u8; 28];
		for (i, &name_char) in name_bytes.iter().enumerate() {
			let bytes = name_char.to_le_bytes();
			raw_bytes[i * 2] = bytes[0];
			raw_bytes[i * 2 + 1] = bytes[1];
		}
		file.write_all(&raw_bytes)?;

		file.seek(SeekFrom::Current(9))?;
		file.write_u8(if self.is_male { 1 } else { 0 })?;
		file.write_u8(self.character_class)?;
		file.write_u8(self.body_type)?;
		file.write_u8(self.starting_gift)?;

		file.seek(SeekFrom::Current(63))?;
		file.write_u8(self.poison_resistance)?;
		file.write_u8(self.bleeding_resistance)?;
		file.write_u8(self.poison_resistance2)?;
		file.write_u8(self.damnation_resistance)?;

		file.write_u8(self.face)?;
		file.write_u8(self.hair)?;
		file.write_u8(self.hair_color)?;

		file.seek(SeekFrom::Start(127_448))?;
		file.write_u32::<LittleEndian>(self.deaths)?;

		Ok(())
	}
}

#[allow(dead_code)]
#[derive(Debug)]
struct Bnd4Entry {
	raw: Vec<u8>,
	index: usize,
	decrypted_slot_path: Option<String>,
	size: usize,
	data_offset: usize,
	name_offset: usize,
	footer_length: usize,
	name: String,
	iv: Vec<u8>,
	encrypted_data: Vec<u8>,
	decrypted_data: Vec<u8>,
	checksum: Vec<u8>,
	decrypted: bool,
	decrypted_data_length: usize,
	character_name: String,
	character_stats: Option<CharacterStats>,
}

impl Bnd4Entry {
	fn new(
		raw: Vec<u8>,
		index: usize,
		decrypted_slot_path: Option<String>,
		size: usize,
		data_offset: usize,
		name_offset: usize,
		footer_length: usize,
	) -> Bnd4Entry {
		let name = String::from_utf16(
			&raw[name_offset..name_offset + 24]
				.chunks_exact(2)
				.map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
				.collect::<Vec<u16>>(),
		)
		.expect("Could not retrieve character name");

		let iv = raw[data_offset + 16..data_offset + 32].to_vec();
		let encrypted_data = raw[data_offset + 16..data_offset + size].to_vec();
		let checksum = raw[data_offset..data_offset + 16].to_vec();

		Self {
			raw,
			index,
			decrypted_slot_path,
			size,
			data_offset,
			name_offset,
			footer_length,
			name,
			iv,
			encrypted_data,
			decrypted_data: Vec::new(),
			checksum,
			decrypted: false,
			decrypted_data_length: 0,
			character_name: String::new(),
			character_stats: None,
		}
	}

	fn decrypt(&mut self) -> Result<(), Error> {
		type AesCbc = cbc::Decryptor<Aes128>;

		let decrypted = AesCbc::new(&DSR_KEY.into(), self.iv.as_slice().into())
			.decrypt_padded_mut::<Pkcs7>(&mut self.encrypted_data)
			.map_err(|_| Error::new(ErrorKind::InvalidData, "Decryption failed"))?;

		let data_length = u32::from_le_bytes(decrypted[16..20].try_into().unwrap()) as usize;
		self.decrypted_data = decrypted[20..20 + data_length].to_vec();

		if let Some(path) = &self.decrypted_slot_path {
			fs::create_dir_all(path)?;
			let full_path = Path::new(path).join(&self.name);
			File::create(full_path)?.write_all(&self.decrypted_data)?;
		}

		self.decrypted = true;
		Ok(())
	}
	fn custom_pkcs7_padding(&self) -> Vec<u8> {
		let pad_len = 16 - ((self.decrypted_data.len() + 4) % 16);

		if pad_len == 16 {
			return Vec::new();
		}

		vec![pad_len as u8; pad_len]
	}

	fn load_character_stats(&mut self) -> Result<(), Error> {
		if !self.decrypted {
			self.decrypt()?;
		}

		let temp_path = format!("temp_slot_{}.sl2", self.index);
		{
			let mut temp_file = File::create(&temp_path)?;
			temp_file.write_all(&self.decrypted_data)?;
		}

		match CharacterStats::deserialize(&temp_path) {
			Ok(stats) => {
				self.character_stats = Some(stats);
				fs::remove_file(temp_path)?;
				Ok(())
			},
			Err(e) => {
				fs::remove_file(temp_path)?;
				Err(Error::new(
					ErrorKind::InvalidData,
					format!("Failed to load character stats: {e}"),
				))
			},
		}
	}

	fn modify_character_stats(&mut self, new_stats: CharacterStats) -> Result<Vec<u8>, Error> {
		if !self.decrypted {
			self.decrypt()?;
		}

		let temp_path = format!("temp_slot_{}.sl2", self.index);
		{
			let mut temp_file = File::create(&temp_path)?;
			temp_file.write_all(&self.decrypted_data)?;
		}

		new_stats.serialize(&temp_path)?;

		let mut modified_file = File::open(&temp_path)?;
		let mut modified_data = Vec::new();
		modified_file.read_to_end(&mut modified_data)?;
		fs::remove_file(temp_path)?;

		type AesCbc = Encryptor<Aes128>;
		let encryptor = AesCbc::new(&DSR_KEY.into(), self.iv.as_slice().into());

		let mut to_encrypt = Vec::new();
		to_encrypt.extend_from_slice(&(modified_data.len() as u32).to_le_bytes());
		to_encrypt.extend_from_slice(&modified_data);
		to_encrypt.extend_from_slice(&self.custom_pkcs7_padding());

		let padded_len = to_encrypt.len() + (16 - (to_encrypt.len() % 16));
		let mut encrypted_data = vec![0; padded_len];

		encrypted_data[..to_encrypt.len()].copy_from_slice(&to_encrypt);

		let encrypted_len = encryptor
			.encrypt_padded_mut::<Pkcs7>(&mut encrypted_data, to_encrypt.len())
			.map_err(|_| Error::new(ErrorKind::InvalidData, "Encryption failed"))?
			.len();

		let encrypted_data = encrypted_data[..encrypted_len].to_vec();

		let checksum = md5::compute(&encrypted_data).to_vec();

		let mut new_raw = self.raw.clone();
		new_raw[self.data_offset..self.data_offset + 16].copy_from_slice(&checksum);
		new_raw[self.data_offset + 16..self.data_offset + self.size].copy_from_slice(&encrypted_data);

		Ok(new_raw)
	}

	fn get_slot_occupancy(&mut self) -> Result<HashMap<usize, String>, Error> {
		if self.index != 10 {
			return Err(Error::new(
				ErrorKind::InvalidInput,
				"Can only call get_slot_occupancy on entry #10",
			));
		}

		if !self.decrypted {
			self.decrypt()?;
		}

		let mut slot_occupancy = HashMap::new();
		let slot_bytes = &self.decrypted_data[176..186];

		for i in 0..10 {
			if slot_bytes[i] != 0 {
				let name_offset = 192 + (400 * i);
				let name_bytes = &self.decrypted_data[name_offset..name_offset + 26];

				let name = String::from_utf16(
					&name_bytes
						.chunks_exact(2)
						.take_while(|chunk| chunk[0] != 0 || chunk[1] != 0)
						.map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
						.collect::<Vec<u16>>(),
				)
				.expect("Could not get slot information");

				slot_occupancy.insert(i, name);
			}
		}

		Ok(slot_occupancy)
	}
}

fn prompt_character_stats(
	existing_stats: Option<&CharacterStats>,
) -> Result<CharacterStats, Box<dyn std::error::Error>> {
	let base_stats = existing_stats.cloned().unwrap_or(CharacterStats {
		health_current: 0,
		health_max1: 400,
		health_max2: 400,
		stamina2: 0,
		stamina3: 0,
		vitality: 10,
		attunement: 10,
		endurance: 10,
		strength: 10,
		dexterity: 10,
		intelligence: 10,
		faith: 10,
		humanity: 0,
		resistance: 10,
		level: 1,
		souls: 0,
		earned_souls: 0,
		soul_state: SoulState::Human,
		name: String::new(),
		is_male: true,
		character_class: 0,
		body_type: 0,
		starting_gift: 0,
		poison_resistance: 0,
		bleeding_resistance: 0,
		poison_resistance2: 0,
		damnation_resistance: 0,
		face: 0,
		hair: 0,
		hair_color: 0,
		deaths: 0,
	});

	let name = Text::new("Character Name:").with_default(&base_stats.name).prompt()?;

	let level = Text::new("Level:")
		.with_default(&base_stats.level.to_string())
		.prompt()?
		.parse()?;

	let souls = Text::new("Souls:")
		.with_default(&base_stats.souls.to_string())
		.prompt()?
		.parse()?;

	let strength = Text::new("Strength:")
		.with_default(&base_stats.strength.to_string())
		.prompt()?
		.parse()?;

	let dexterity = Text::new("Dexterity:")
		.with_default(&base_stats.dexterity.to_string())
		.prompt()?
		.parse()?;

	let intelligence = Text::new("Intelligence:")
		.with_default(&base_stats.intelligence.to_string())
		.prompt()?
		.parse()?;

	let faith = Text::new("Faith:")
		.with_default(&base_stats.faith.to_string())
		.prompt()?
		.parse()?;

	let vitality = Text::new("Vitality:")
		.with_default(&base_stats.vitality.to_string())
		.prompt()?
		.parse()?;

	let endurance = Text::new("Endurance:")
		.with_default(&base_stats.endurance.to_string())
		.prompt()?
		.parse()?;

	let humanity = Text::new("Humanity:")
		.with_default(&base_stats.humanity.to_string())
		.prompt()?
		.parse()?;

	let health_max = Text::new("Max Health:")
		.with_default(&base_stats.health_max1.to_string())
		.prompt()?
		.parse()?;

	let character_class = Text::new("Character Class (0-11):")
		.with_default(&base_stats.character_class.to_string())
		.prompt()?
		.parse()?;

	let is_male = Confirm::new("Is the character male?")
		.with_default(base_stats.is_male)
		.prompt()?;

	Ok(CharacterStats {
		name,
		level,
		souls,
		strength,
		dexterity,
		intelligence,
		faith,
		vitality,
		endurance,
		humanity,
		health_current: health_max,
		health_max1: health_max,
		health_max2: health_max,
		character_class,
		is_male,
		..base_stats
	})
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	println!("Dark Souls Remastered Save File Editor - Enhanced Mode");

	let input_sl2 = Text::new("Enter the path to the SL2 save file:").prompt()?;
	let output_sl2 = Text::new("Enter the path to save the output SL2 file:").prompt()?;

	let keep_decrypted_slots = Text::new("Enter the directory to save decrypted slots (optional):")
		.with_default("")
		.prompt()?;
	let keep_decrypted_slots = if keep_decrypted_slots.is_empty() {
		None
	} else {
		Some(keep_decrypted_slots)
	};

	let list_slots = Confirm::new("Do you want to list the active slots?")
		.with_default(false)
		.prompt()?;

	let mut file = File::open(&input_sl2)?;
	let mut raw = Vec::new();
	file.read_to_end(&mut raw)?;

	if &raw[0..4] != b"BND4" {
		return Err("Not a valid BND4 file".into());
	}

	let num_bnd4_entries = u32::from_le_bytes(raw[12..16].try_into().unwrap()) as usize;

	const BND4_HEADER_LEN: usize = 64;
	const BND4_ENTRY_HEADER_LEN: usize = 32;

	let mut bnd4_entries = Vec::new();
	let mut slot_occupancy = HashMap::new();

	for i in 0..num_bnd4_entries {
		let pos = BND4_HEADER_LEN + (BND4_ENTRY_HEADER_LEN * i);
		let entry_header = &raw[pos..pos + BND4_ENTRY_HEADER_LEN];

		if entry_header[0..8] != [0x50, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff] {
			return Err(format!("Entry header #{i} does not match expected magic value").into());
		}

		let entry_size = u32::from_le_bytes(entry_header[8..12].try_into().unwrap()) as usize;
		let entry_data_offset = u32::from_le_bytes(entry_header[16..20].try_into().unwrap()) as usize;
		let entry_name_offset = u32::from_le_bytes(entry_header[20..24].try_into().unwrap()) as usize;
		let entry_footer_length = u32::from_le_bytes(entry_header[24..28].try_into().unwrap()) as usize;

		let mut entry = Bnd4Entry::new(
			raw.clone(),
			i,
			keep_decrypted_slots.clone(),
			entry_size,
			entry_data_offset,
			entry_name_offset,
			entry_footer_length,
		);

		entry.decrypt()?;

		if i == 10 {
			slot_occupancy = entry.get_slot_occupancy()?;
		}

		bnd4_entries.push(entry);
	}

	if list_slots {
		for (slot, name) in slot_occupancy.iter() {
			println!("Slot #{slot} occupied; character name: [{name}]");
		}
		return Ok(());
	}

	let slot_selection = Select::new("Choose the slot to edit:", vec!["Edit All Slots", "Specify a Slot"]).prompt()?;

	let slot = if slot_selection == "Specify a Slot" {
		Text::new("Enter the slot number to edit (0-9):")
			.with_default("0")
			.prompt()?
			.parse()?
	} else {
		-1
	};

	if slot > 9 || slot < -1 {
		return Err("Slot number must be between 0 and 9".into());
	}

	for (i, entry) in bnd4_entries.iter_mut().enumerate() {
		if let Some(name) = slot_occupancy.get(&i) {
			entry.character_name = name.clone();

			entry.load_character_stats()?;

			if (slot >= 0 && i == slot as usize) || slot == -1 {
				println!("\nEditing Slot #{i} - Character: {name}");

				if let Some(current_stats) = &entry.character_stats {
					let new_stats = prompt_character_stats(Some(current_stats))?;
					raw = entry.modify_character_stats(new_stats)?;
				}
			}
		}
	}

	let mut output_file = File::create(&output_sl2)?;
	output_file.write_all(&raw)?;
	println!("\nDONE! Wrote to output file: {output_sl2}");

	Ok(())
}
