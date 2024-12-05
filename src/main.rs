use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

const USER_DATA_SIZE: usize = 0x06_0020;
const SAVE_FILE_SIZE: usize = 0x42_04D0;
const SAVE_SLOT_SIZE: usize = 0x06_0030;
const BASE_SLOT_OFFSET: usize = 0x02C0;
const USER_DATA_FILE_CNT: usize = 11;

const KEY: [u8; 16] = [
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
];

fn cbc_decrypt(key: &[u8], iv: &[u8], data: &mut [u8]) {
	let cipher = Aes128::new(GenericArray::from_slice(key));
	let block_size = 16;

	let mut previous_block = [0u8; 16];
	previous_block.copy_from_slice(iv);

	for i in (0..data.len()).step_by(block_size) {
		if i + block_size > data.len() {
			break;
		}
		let mut block = GenericArray::clone_from_slice(&data[i..i + block_size]);
		let current_encrypted_block = block;

		cipher.decrypt_block(&mut block);
		for j in 0..block_size {
			data[i + j] = block[j] ^ previous_block[j];
		}

		previous_block.copy_from_slice(&current_encrypted_block);
	}
}

fn cbc_encrypt(key: &[u8], iv: &[u8], data: &mut [u8]) {
	let cipher = Aes128::new(GenericArray::from_slice(key));
	let block_size = 16;

	let mut previous_block = [0u8; 16];
	previous_block.copy_from_slice(iv);

	for i in (0..data.len()).step_by(block_size) {
		if i + block_size > data.len() {
			break;
		}

		for j in 0..block_size {
			data[i + j] ^= previous_block[j];
		}

		let mut block = GenericArray::clone_from_slice(&data[i..i + block_size]);

		cipher.encrypt_block(&mut block);
		previous_block.copy_from_slice(&block);
		data[i..i + block_size].copy_from_slice(&block);
	}
}

fn decrypt_save_slot(save_slot_buffer: &mut [u8]) {
	let mut iv = [0u8; 16];
	iv.copy_from_slice(&save_slot_buffer[..16]);

	let encrypted_data = &mut save_slot_buffer[16..16 + USER_DATA_SIZE];
	cbc_decrypt(&KEY, &iv, encrypted_data);
}

fn encrypt_save_slot(save_slot_buffer: &mut [u8], iv: &[u8]) {
	let encrypted_data = &mut save_slot_buffer[16..16 + USER_DATA_SIZE];
	cbc_encrypt(&KEY, iv, encrypted_data);
}

fn unpack_save_file(input_file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
	println!("----------------------------");
	println!("B3's DSR save file unpacker.");
	println!("----------------------------\n");

	let mut save_file_buffer = vec![0u8; SAVE_FILE_SIZE];
	let mut input_file = File::open(input_file_path)?;
	input_file.read_exact(&mut save_file_buffer)?;

	println!("Unpacking... ");

	for i in 0..USER_DATA_FILE_CNT {
		let start = BASE_SLOT_OFFSET + i * SAVE_SLOT_SIZE;
		let mut current_save_slot = save_file_buffer[start..start + SAVE_SLOT_SIZE].to_vec();

		decrypt_save_slot(&mut current_save_slot);

		let filename = format!("USER_DATA{i:03}");
		let mut output_file = File::create(&filename)?;
		output_file.write_all(&current_save_slot[16..16 + USER_DATA_SIZE])?;
	}

	println!("Success!");
	Ok(())
}

fn pack_save_file(output_file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
	println!("----------------------------");
	println!("B3's DSR save file packer.");
	println!("----------------------------\n");

	let mut save_file_buffer = vec![0u8; SAVE_FILE_SIZE];

	println!("Packing... ");

	for i in 0..USER_DATA_FILE_CNT {
		let filename = format!("USER_DATA{i:03}");
		let input_path = Path::new(&filename);

		if !input_path.exists() {
			return Err(format!("File {filename} not found").into());
		}

		let mut user_data = vec![0u8; USER_DATA_SIZE];
		let mut input_file = File::open(input_path)?;
		input_file.read_exact(&mut user_data)?;

		let mut save_slot_buffer = vec![0u8; SAVE_SLOT_SIZE];

		let iv = [0u8; 16];
		save_slot_buffer[..16].copy_from_slice(&iv);

		save_slot_buffer[16..16 + USER_DATA_SIZE].copy_from_slice(&user_data);

		encrypt_save_slot(&mut save_slot_buffer, &iv);

		let start = BASE_SLOT_OFFSET + i * SAVE_SLOT_SIZE;
		save_file_buffer[start..start + SAVE_SLOT_SIZE].copy_from_slice(&save_slot_buffer);
	}

	let mut output_file = File::create(output_file_path)?;
	output_file.write_all(&save_file_buffer)?;

	println!("Success!");
	Ok(())
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
	#[command(subcommand)]
	command: Commands,
}

#[derive(Subcommand)]
enum Commands {
	Pack { output: String },
	Unpack { input: String },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let cli = Cli::parse();

	match cli.command {
		Commands::Unpack { input } => unpack_save_file(&input)?,
		Commands::Pack { output } => pack_save_file(&output)?,
	}

	Ok(())
}
