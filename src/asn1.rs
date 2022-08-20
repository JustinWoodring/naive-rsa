use asn1_rs::{BigInt, BigUint, Error, FromDer, Integer, Sequence, Tag, Tagged, ToDer};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RSAPublicKey {
    pub modulus: BigUint,         //n
    pub public_exponent: BigUint, //e
}

impl RSAPublicKey {
    fn get_sequence(&self) -> Sequence {
        let mut writer = Vec::new();
        Integer::new(&BigInt::from(self.modulus.clone()).to_signed_bytes_be())
            .write_der(&mut writer)
            .expect("Oh noez");
        Integer::new(&BigInt::from(self.public_exponent.clone()).to_signed_bytes_be())
            .write_der(&mut writer)
            .expect("Oh noez");

        Sequence::new(writer.into())
    }

    pub fn to_pkcs1_pem_string(&self) -> String {
        let mut string = String::new();
        string += "-----BEGIN RSA PUBLIC KEY-----\n";

        let mut text = base64::encode(&self.to_der_vec().unwrap());
        loop {
            let text_clone = text.clone();
            let (curr_text, remaining_text) = text_clone.split_at(64);
            text = remaining_text.to_string();

            string += &(curr_text.to_owned() + "\n");

            if remaining_text.len() <= 64 {
                string += &(remaining_text.to_owned() + "\n");
                break;
            }
        }

        string += "-----END RSA PUBLIC KEY-----\n";

        string
    }

    pub fn to_pkcs1_der_vec(&self) -> Vec<u8> {
        self.to_der_vec().unwrap()
    }
}

impl From<RSAPrivateKey> for RSAPublicKey {
    fn from(key: RSAPrivateKey) -> Self {
        Self {
            modulus: key.modulus,
            public_exponent: key.public_exponent,
        }
    }
}

impl From<&RSAPrivateKey> for RSAPublicKey {
    fn from(key: &RSAPrivateKey) -> Self {
        Self {
            modulus: key.modulus.clone(),
            public_exponent: key.public_exponent.clone(),
        }
    }
}

impl Tagged for RSAPublicKey {
    const TAG: asn1_rs::Tag = Tag(16);
}

/*
impl FromDer<'_> for RSAPublicKey {
    fn from_der(i: &[u8]) -> asn1_rs::ParseResult<Self, Error> {
        let value = Sequence::from_der_and_then(i, |i| {
            let (i, a) = BigInt::from_der(i).unwrap();
            let (i, b) = BigInt::from_der(i).unwrap();
            Ok((i, (a, b)))
        });

        value
    }
}*/

impl ToDer for RSAPublicKey {
    fn to_der_len(&self) -> asn1_rs::Result<usize> {
        self.get_sequence().to_der_len()
    }

    fn write_der_header(&self, writer: &mut dyn std::io::Write) -> asn1_rs::SerializeResult<usize> {
        self.get_sequence().write_der_header(writer)
    }

    fn write_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        self.get_sequence().write_der_content(writer)
    }

    fn to_der_vec(&self) -> asn1_rs::SerializeResult<Vec<u8>> {
        let mut v = Vec::new();
        let _ = self.write_der(&mut v)?;
        Ok(v)
    }

    fn to_der_vec_raw(&self) -> asn1_rs::SerializeResult<Vec<u8>> {
        let mut v = Vec::new();
        let _ = self.write_der_raw(&mut v)?;
        Ok(v)
    }

    fn write_der(&self, writer: &mut dyn std::io::Write) -> asn1_rs::SerializeResult<usize> {
        let sz = self.write_der_header(writer)?;
        let sz = sz + self.write_der_content(writer)?;
        Ok(sz)
    }

    fn write_der_raw(&self, writer: &mut dyn std::io::Write) -> asn1_rs::SerializeResult<usize> {
        self.write_der(writer)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RSAPrivateKey {
    pub version: BigUint,          // 0
    pub modulus: BigUint,          // n
    pub public_exponent: BigUint,  // e
    pub private_exponent: BigUint, // d
    pub prime1: BigUint,           // p
    pub prime2: BigUint,           // q
    pub exponent1: BigUint,        // d mod (p-1)
    pub exponent2: BigUint,        // d mod (q-1)
    pub coefficient: BigUint,      // q_inv mod p
}

impl RSAPrivateKey {
    fn get_sequence(&self) -> Sequence {
        let mut writer = Vec::new();
        Integer::new(&BigInt::from(self.version.clone()).to_signed_bytes_be())
            .write_der(&mut writer)
            .expect("Oh noez");
        Integer::new(&BigInt::from(self.modulus.clone()).to_signed_bytes_be())
            .write_der(&mut writer)
            .expect("Oh noez");
        Integer::new(&BigInt::from(self.public_exponent.clone()).to_signed_bytes_be())
            .write_der(&mut writer)
            .expect("Oh noez");
        Integer::new(&BigInt::from(self.private_exponent.clone()).to_signed_bytes_be())
            .write_der(&mut writer)
            .expect("Oh noez");
        Integer::new(&BigInt::from(self.prime1.clone()).to_signed_bytes_be())
            .write_der(&mut writer)
            .expect("Oh noez");
        Integer::new(&BigInt::from(self.prime2.clone()).to_signed_bytes_be())
            .write_der(&mut writer)
            .expect("Oh noez");
        Integer::new(&BigInt::from(self.exponent1.clone()).to_signed_bytes_be())
            .write_der(&mut writer)
            .expect("Oh noez");
        Integer::new(&BigInt::from(self.exponent2.clone()).to_signed_bytes_be())
            .write_der(&mut writer)
            .expect("Oh noez");
        Integer::new(&BigInt::from(self.coefficient.clone()).to_signed_bytes_be())
            .write_der(&mut writer)
            .expect("Oh noez");

        Sequence::new(writer.into())
    }

    pub fn to_pkcs1_pem_string(&self) -> String {
        let mut string = String::new();
        string += "-----BEGIN RSA PRIVATE KEY-----\n";

        let mut text = base64::encode(&self.to_der_vec().unwrap());
        loop {
            let text_clone = text.clone();
            let (curr_text, remaining_text) = text_clone.split_at(64);
            text = remaining_text.to_string();

            string += &(curr_text.to_owned() + "\n");

            if remaining_text.len() <= 64 {
                string += &(remaining_text.to_owned() + "\n");
                break;
            }
        }

        string += "-----END RSA PRIVATE KEY-----\n";

        string
    }

    pub fn to_pkcs1_der_vec(&self) -> Vec<u8> {
        self.to_der_vec().unwrap()
    }
}

impl Tagged for RSAPrivateKey {
    const TAG: asn1_rs::Tag = Tag(16);
}

impl ToDer for RSAPrivateKey {
    fn to_der_len(&self) -> asn1_rs::Result<usize> {
        self.get_sequence().to_der_len()
    }

    fn write_der_header(&self, writer: &mut dyn std::io::Write) -> asn1_rs::SerializeResult<usize> {
        self.get_sequence().write_der_header(writer)
    }

    fn write_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        self.get_sequence().write_der_content(writer)
    }

    fn to_der_vec(&self) -> asn1_rs::SerializeResult<Vec<u8>> {
        let mut v = Vec::new();
        let _ = self.write_der(&mut v)?;
        Ok(v)
    }

    fn to_der_vec_raw(&self) -> asn1_rs::SerializeResult<Vec<u8>> {
        let mut v = Vec::new();
        let _ = self.write_der_raw(&mut v)?;
        Ok(v)
    }

    fn write_der(&self, writer: &mut dyn std::io::Write) -> asn1_rs::SerializeResult<usize> {
        let sz = self.write_der_header(writer)?;
        let sz = sz + self.write_der_content(writer)?;
        Ok(sz)
    }

    fn write_der_raw(&self, writer: &mut dyn std::io::Write) -> asn1_rs::SerializeResult<usize> {
        self.write_der(writer)
    }
}
