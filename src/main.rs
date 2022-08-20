use std::{fs::File, io::Write, path::PathBuf, thread, time::Duration};

use naive_rsa::{
    asn1::RSAPublicKey,
    rsa::{encrypt::rsaes_pkcs1_v1_5_encrypt, gen_keypair::generate_keypair},
};
use simple_logger::SimpleLogger;

fn main() {
    let arguments: Vec<String> = std::env::args().collect();

    if arguments.contains(&"--debug".to_string()) {
        SimpleLogger::new().init().unwrap();
    }

    println!(
        "\n\u{001b}[35;1mNaiveRSA\u{001b}[0;1m ~ A naive MIT-licensed RSA implementation by Justin Woodring\u{001b}[0m"
    );

    if arguments.contains(&"--interactive".to_string()) {
        let operations = vec!["Exit", "Generate Keypair", "Encrypt Message"];

        let selection = loop {
            println!("\n\u{001b}[33;1mAvailable Operations\u{001b}[0m");
            for (i, &my_string) in operations.iter().enumerate() {
                println!("  \u{001b}[32;1m{}\u{001b}[0m: {}", i, my_string);
            }

            print!("\nSelect an operation (0-{})> ", operations.len() - 1);
            let _unused = std::io::stdout().flush();

            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();

            if let Ok(num) = input.trim().parse::<u32>() {
                if num >= 0 && num < operations.len().try_into().unwrap() {
                    break num;
                } else {
                    println!("\u{001b}[31;1mInvalid selection\u{001b}[0m");
                }
            } else {
                println!("\u{001b}[31;1mInvalid selection\u{001b}[0m");
            }
        };

        match selection {
            1 => create_keypair_dialog(),
            2 => encrypt_message_dialog(),
            _ => {}
        }

        println!("\n\u{001b}[0;1mThank you for using \u{001b}[0m\u{001b}[35;1mNaiveRSA\u{001b}[0m\u{001b}[0;1m!\u{001b}[0m");
    }
}

fn create_keypair_dialog() {
    let key_sizes = vec!["512", "1024", "2048", "3072", "4096", "8192"];
    let selection = loop {
        println!("\n\u{001b}[33;1mAvailable Keysizes\u{001b}[0m");
        for (i, &my_string) in key_sizes.iter().enumerate() {
            println!("  \u{001b}[32;1m{}\u{001b}[0m: {}", i, my_string);
        }

        print!(
            "\nSelect an key size [2048 min. recommended] (0-{})> ",
            key_sizes.len() - 1
        );
        let _unused = std::io::stdout().flush();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();

        if let Ok(num) = input.trim().parse::<u32>() {
            if num >= 0 && num < key_sizes.len().try_into().unwrap() {
                break num;
            } else {
                println!("\u{001b}[31;1mInvalid selection\u{001b}[0m");
            }
        } else {
            println!("\u{001b}[31;1mInvalid selection\u{001b}[0m");
        }
    };

    let key_size = key_sizes
        .get(selection as usize)
        .unwrap()
        .to_string()
        .parse::<u32>()
        .unwrap();

    let output_encodings = vec!["PEM", "DER"];
    let selection = loop {
        println!("\n\u{001b}[33;1mAvailable Encodings\u{001b}[0m");
        for (i, &my_string) in output_encodings.iter().enumerate() {
            println!("  \u{001b}[32;1m{}\u{001b}[0m: {}", i, my_string);
        }

        print!("\nSelect an encoding (0-{})> ", output_encodings.len() - 1);
        let _unused = std::io::stdout().flush();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();

        if let Ok(num) = input.trim().parse::<u32>() {
            if num >= 0 && num < output_encodings.len().try_into().unwrap() {
                break num;
            } else {
                println!("\u{001b}[31;1mInvalid selection\u{001b}[0m");
            }
        } else {
            println!("\u{001b}[31;1mInvalid selection\u{001b}[0m");
        }
    };

    let output_encoding = output_encodings
        .get(selection as usize)
        .unwrap()
        .to_string();

    let selection = loop {
        print!(
            "\n\u{001b}[33;1mExport PKCS #1 RSAPublicKey to separate file? (y or n)> \u{001b}[0m"
        );
        let _unused = std::io::stdout().flush();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();

        if "y" == input.trim() || "n" == input.trim() {
            break input.trim().to_string();
        } else {
            println!("\u{001b}[31;1mInvalid selection\u{001b}[0m");
        }
    };

    let export_public_key = if selection == "y" { true } else { false };

    let mut private_key_output_location = PathBuf::new();
    let mut public_key_output_location = PathBuf::new();

    let selection = loop {
        let default = format!("{}.{}", "./private-key", output_encoding.to_lowercase());
        print!(
            "\n\u{001b}[33;1mEnter a destination filename for the RSAPrivateKey ({})> \u{001b}[0m",
            default
        );
        let _unused = std::io::stdout().flush();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        input = input.trim().to_string();
        if input.is_empty() {
            input = default;
        }

        let result = PathBuf::from(input);

        if result.is_dir() {
            println!("\u{001b}[31;1mA directory exists at that location\u{001b}[0m");
        } else {
            break result;
        }
    };

    private_key_output_location = selection;

    if export_public_key {
        let selection = loop {
            let default = format!("{}.{}", "./public-key", output_encoding.to_lowercase());
            print!(
                "\n\u{001b}[33;1mEnter a destination filename for the RSAPublicKey ({})> \u{001b}[0m",
                default
            );
            let _unused = std::io::stdout().flush();

            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input = input.trim().to_string();
            if input.is_empty() {
                input = default;
            }

            let result = PathBuf::from(input);

            if result.is_dir() {
                println!("\u{001b}[31;1mA directory exists at that location\u{001b}[0m");
            } else if result == private_key_output_location {
                println!("\u{001b}[31;1mCan't output two keys to the same location\u{001b}[0m");
            } else {
                break result;
            }
        };

        public_key_output_location = selection;
    }

    println!("\n\n\u{001b}[1mHere are the details of your new RSA key:\n\u{001b}[0m");
    println!("Key size: \t\t\t{}-bit", key_size);
    println!("Output encoding: \t\t{}", output_encoding);
    println!("Export public key: \t\t{}", export_public_key);
    println!(
        "Private key output location: \t{}",
        private_key_output_location.to_string_lossy()
    );
    if export_public_key {
        println!(
            "Public key output location: \t{}",
            public_key_output_location.to_string_lossy()
        );
    }

    let selection = loop {
        print!("\n\u{001b}[33;1mProceed with key generation? (y or n)> \u{001b}[0m");
        let _unused = std::io::stdout().flush();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();

        if "y" == input.trim() || "n" == input.trim() {
            break input.trim().to_string();
        } else {
            println!("\u{001b}[31;1mInvalid selection\u{001b}[0m");
        }
    };

    if selection == "n" {
        println!("\u{001b}[31;1mAborting key generation\u{001b}[0m");
        return ();
    }

    println!("\u{001b}[32;1mProceeding with key generation\u{001b}[0m");

    println!("\nAttempting to open private key");
    let mut private =
        File::create(private_key_output_location).expect("Failed to open file for writing");

    let mut public = None;
    if export_public_key {
        println!("\nAttempting to open public key");
        public = Some(
            File::create(public_key_output_location).expect("Failed to open file for writing"),
        );
    }

    let handle = thread::spawn(move || {
        let private_key = generate_keypair(key_size);
        let public_key = RSAPublicKey::from(&private_key);

        return (private_key, public_key);
    });

    println!("\n\u{001b}[32;1mGenerating keys\u{001b}[0m");
    let mut char = "|";
    loop {
        thread::sleep(Duration::from_millis(100));
        print!("\r~ Computing primes [\u{001b}[32;1m{}\u{001b}[0m]", char);
        let _unused = std::io::stdout().flush();
        if char == "|" {
            char = "/";
        } else if char == "/" {
            char = "-";
        } else if char == "-" {
            char = "\\";
        } else if char == "\\" {
            char = "|";
        }

        if handle.is_finished() {
            break;
        }
    }

    let (private_key, public_key) = handle
        .join()
        .expect("Something went wrong generating the keys...");

    println!("\r~ Computing primes [\u{001b}[32;1mX\u{001b}[0m]");
    println!("~ Computing carmichael totient of p and q [\u{001b}[32;1mX\u{001b}[0m]");
    println!("~ Computing e [\u{001b}[32;1mX\u{001b}[0m]");
    println!("~ Computing d [\u{001b}[32;1mX\u{001b}[0m]");

    if output_encoding == "PEM" {
        private
            .write_all(&private_key.to_pkcs1_pem_string().as_bytes())
            .expect("Failed to write files");
        if export_public_key {
            public
                .unwrap()
                .write_all(&public_key.to_pkcs1_pem_string().as_bytes())
                .expect("Failed to write files");
        }
    } else {
        private
            .write_all(&private_key.to_pkcs1_der_vec())
            .expect("Failed to write files");
        if export_public_key {
            public
                .unwrap()
                .write_all(&public_key.to_pkcs1_der_vec())
                .expect("Failed to write files");
        }
    }

    println!("~ Writing to files [\u{001b}[32;1mX\u{001b}[0m]");
}

fn encrypt_message_dialog() {
    let encryption_protocols = vec!["RSAES-PKCS1-V1_5"];
    let selection = loop {
        println!("\n\u{001b}[33;1mAvailable Encryption Schemes\u{001b}[0m");
        for (i, &my_string) in encryption_protocols.iter().enumerate() {
            println!("  \u{001b}[32;1m{}\u{001b}[0m: {}", i, my_string);
        }

        print!(
            "\nSelect an encryption scheme (0-{})> ",
            encryption_protocols.len() - 1
        );
        let _unused = std::io::stdout().flush();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();

        if let Ok(num) = input.trim().parse::<u32>() {
            if num >= 0 && num < encryption_protocols.len().try_into().unwrap() {
                break num;
            } else {
                println!("\u{001b}[31;1mInvalid selection\u{001b}[0m");
            }
        } else {
            println!("\u{001b}[31;1mInvalid selection\u{001b}[0m");
        }
    };

    let encryption_protocol = encryption_protocols
        .get(selection as usize)
        .unwrap()
        .to_string();

    let input_encodings = vec!["PEM", "DER"];
    let selection = loop {
        println!("\n\u{001b}[33;1mAvailable Encodings\u{001b}[0m");
        for (i, &my_string) in input_encodings.iter().enumerate() {
            println!("  \u{001b}[32;1m{}\u{001b}[0m: {}", i, my_string);
        }

        print!(
            "\nSelect the encoding of recipient's RSAPublicKey file (0-{})> ",
            input_encodings.len() - 1
        );
        let _unused = std::io::stdout().flush();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();

        if let Ok(num) = input.trim().parse::<u32>() {
            if num >= 0 && num < input_encodings.len().try_into().unwrap() {
                break num;
            } else {
                println!("\u{001b}[31;1mInvalid selection\u{001b}[0m");
            }
        } else {
            println!("\u{001b}[31;1mInvalid selection\u{001b}[0m");
        }
    };

    let input_encoding = input_encodings.get(selection as usize).unwrap().to_string();

    let selection = loop {
        let default = format!(
            "{}.{}",
            "./recipient-public-key",
            input_encoding.to_lowercase()
        );
        print!(
            "\n\u{001b}[33;1mEnter the filepath of the intended recipient's RSAPublicKey file ({})> \u{001b}[0m",
            default
        );
        let _unused = std::io::stdout().flush();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        input = input.trim().to_string();
        if input.is_empty() {
            input = default;
        }

        let result = PathBuf::from(input);

        if !result.is_file() {
            println!("\u{001b}[31;1mNo file exists at that location\u{001b}[0m");
        } else {
            break result;
        }
    };

    let public_key_file_location = selection;

    println!("\nAttempting to open public key");
    let public =
        File::open(public_key_file_location.clone()).expect("Failed to open file for reading");

    let selection = loop {
        let mut max_message_size = -1;
        if encryption_protocol == "RSAES-PKCS1-V1_5" {
            max_message_size = 2048 - 11;
        }
        print!(
            "\n\u{001b}[33;1mEnter a message ({} bytes total)> \u{001b}[0m",
            max_message_size
        );
        let _unused = std::io::stdout().flush();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        input = input.trim().to_string();
        if !input.is_empty() {
            break input;
        }
    };

    let message = selection;

    println!("\n\n\u{001b}[1mHere are the details of the message to encrypt:\n\u{001b}[0m");
    println!("Encryption scheme: \t\t{}", encryption_protocol);
    println!("Recipient's RSAPublicKey encoding: \t{}", input_encoding);
    println!(
        "Public key file location: \t{}",
        public_key_file_location.to_string_lossy()
    );
    println!("Message: \n\n{}", message);

    let selection = loop {
        print!("\n\u{001b}[33;1mProceed with encryption? (y or n)> \u{001b}[0m");
        let _unused = std::io::stdout().flush();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();

        if "y" == input.trim() || "n" == input.trim() {
            break input.trim().to_string();
        } else {
            println!("\u{001b}[31;1mInvalid selection\u{001b}[0m");
        }
    };

    if selection == "n" {
        println!("\u{001b}[31;1mAborting encryption\u{001b}[0m");
        return ();
    }

    println!("\u{001b}[32;1mProceeding with encryption\u{001b}[0m");

    println!("\n\u{001b}[32;1mEncrypting message\u{001b}[0m");
}

/*
let key = generate_keypair(512);

let mut file = File::create("private-rsa-key.der").unwrap();
file.write_all(&key.to_pkcs1_der_vec())
    .expect("Failed to write file!");

let mut file = File::create("private-rsa-key.pem").unwrap();
write!(file, "{}", &key.to_pkcs1_pem_string()).unwrap();

let mut file = File::create("public-rsa-key.pem").unwrap();
write!(file, "{}", RSAPublicKey::from(&key).to_pkcs1_pem_string()).unwrap();*/
