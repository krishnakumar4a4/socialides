//use crypto_operations;
extern crate sodiumoxide;
use sodiumoxide::crypto::box_;
#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;

//DB stuff
extern crate rusqlite;
use self::rusqlite::Connection;
use self::rusqlite::{Result};

#[derive(Serialize, Debug)]
struct DetailRecord {
    id: i32,
    description: String,
    data: Vec<u8>,
    data_type: String
}
#[derive(Serialize, Debug)]
struct Details <'a>{
    id: i32,
    detail_record_ids: Vec<&'a DetailRecord>
}

#[derive(Serialize, Debug)]
struct Profile <'a>{
    id: i32,
    description: String,
    detail_record_ids: Vec<&'a DetailRecord>,
    profile_specific_records: Vec<&'a ProfileSpecificRecord>
}

#[derive(Serialize, Debug)]
struct ProfileSpecificRecord {
    id: i32,
    description: String,
    data: Vec<u8>,
    data_type: String
}

fn main () {
    println!("Hello, world!");

    //Serialization stuff
    trait ToString where Self: serde::Serialize {
        fn tostring(&self) -> String{
            let serialized = serde_json::to_string(&self).unwrap();
            return serialized;
        }
    }

    impl ToString for DetailRecord {
    }
    impl<'a> ToString for Details<'a> {
    }
    impl ToString for ProfileSpecificRecord {
    }
    impl<'a> ToString for Profile<'a> {
    }

    //Sample data
    let dr1 = DetailRecord { id: 1, description: String::from("name"), data: String::from("Krishna").into_bytes(), data_type: String::from("String")};
    let dr2 = DetailRecord { id: 2, description: String::from("address"), data: String::from("On Earth").into_bytes(), data_type: String::from("String")};
    let dr3 = DetailRecord { id: 2, description: String::from("aadhar"), data: String::from("111111111111").into_bytes(), data_type: String::from("String")};

    let d1 = Details {id: 1, detail_record_ids: vec![&dr1, &dr2, &dr3]};

    let ps1 = ProfileSpecificRecord {id: 1, description: String::from("dob"), data: String::from("00/00/1000").into_bytes(), data_type: String::from("date")};
    let p1 = Profile {id:1, description: String::from("aadhar"), detail_record_ids: vec![&dr1, &dr3], profile_specific_records: vec![&ps1]};
    let p1 = Profile {id:2, description: String::from("personal"), detail_record_ids: vec![&dr1, &dr2], profile_specific_records: vec![]};

    println!("p1 string {}",p1.tostring());
    println!("d1 string {}",d1.tostring());
    println!("dr1 string {}",dr1.tostring());
    println!("ps1 string {}",ps1.tostring());

        let (ourpk, oursk) = generate_new_keypair();
        let (theirpk, theirsk) = generate_new_keypair();
        let our_precomputed_key = precompute(&theirpk, &oursk);
        let nonce = get_nonce();
        let plaintext = p1.tostring().to_owned();
        let ciphertext = encrypt(plaintext.as_bytes(), &nonce, &our_precomputed_key);
        // this will be identical to our_precomputed_key
        let their_precomputed_key = precompute(&ourpk, &theirsk);
        let their_plaintext = decrypt(&ciphertext, &nonce,
                                                     &their_precomputed_key);
        assert!(plaintext.as_bytes() == &their_plaintext[..]);
        println!("printing opened {:?}", String::from_utf8_lossy(&their_plaintext[..]));

    let handle = open_connection("./testDB").unwrap();
    setup_db(&handle);
    insert_detail_record(&handle, &dr1);
    let output: Result<Vec<u8>> = handle.query_row("SELECT * from DetailRecord",&[], |row| row.get(2));
    println!("row value is {:?}",output);
}

pub fn generate_new_keypair() -> (box_::PublicKey, box_::SecretKey){
    return box_::gen_keypair();
}

pub fn get_nonce() -> box_::Nonce{
    return box_::gen_nonce();
}

pub fn precompute(pk: &box_::PublicKey, sk: &box_::SecretKey) -> box_::PrecomputedKey {
    return box_::precompute(pk, sk);
}

pub fn encrypt(data: &[u8], nonce: &box_::Nonce, precomputed: &box_::PrecomputedKey) -> Vec<u8> {
    return box_::seal_precomputed(data, nonce,
                           precomputed);
}

pub fn decrypt(encrypted_data: &Vec<u8>, nonce: &box_::Nonce, precomputed: &box_::PrecomputedKey) -> Vec<u8> {
    return box_::open_precomputed(&encrypted_data, &nonce,
                           precomputed).unwrap();
}

//DB operations
pub fn open_connection(path: &str) -> Result<Connection>{
    return Connection::open(path);
}

pub fn setup_db(handle: &Connection) -> Result<()>{
    return handle.execute_batch("BEGIN;
    CREATE TABLE IF NOT EXISTS DetailRecord (
    id INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    data TEXT NOT NULL,
    data_type TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS Details (
    id INTEGER PRIMARY KEY,
    detail_record_ids TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS Profile (
    id INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    detail_record_ids TEXT NOT NULL,
    profile_specific_records TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS ProfileSpecificRecord (
    id INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    data TEXT NOT NULL,
    data_type TEXT NOT NULL);
    COMMIT;");
}

fn insert_detail_record(handle: &Connection, detail_record: &DetailRecord) -> Result<i64>{
    match handle.execute("INSERT INTO DetailRecord (description, data, data_type) VALUES (?1, ?2, ?3)",&[&detail_record.description, &detail_record.data, &detail_record.data_type]){
        Ok(_) => Ok(handle.last_insert_rowid()),
        Err(E) => Err(E)
    }
}

fn insert_details(handle: Connection, details: &Details) -> Vec<Result<i32>>{
    let dris = &details.detail_record_ids;
    //Check if the corresponding detailrecord entries are present in DetailRecord table
    dris.iter().map(|detail_record| {
        //Break and err if one of the insert fails
        handle.execute("INSERT INTO Details (detail_record_ids) VALUES (?1)",&[&detail_record.id])
    }).collect()
}

fn insert_profile(handle: Connection, profile: &Profile) -> Result<i64>{
    let dris = &profile.detail_record_ids;
    let psrs = &profile.profile_specific_records;

    let mut dris_str = dris.iter().fold("".to_owned(),|mut dris_str, detail_record| {
        let mut comma_appended = detail_record.id.to_string();
        comma_appended.push_str(",");
        dris_str.push_str(&comma_appended[..]);
        dris_str
    });
    let mut psrs_str = psrs.iter().fold("".to_owned(), |mut psrs_str, psr| {
        let mut comma_appended = psr.id.to_string();
        comma_appended.push_str(",");
        psrs_str.push_str(&comma_appended[..]);
        psrs_str
    });
    match handle.execute("INSERT INTO Profile (description, detail_record_ids, profile_specific_records) VALUES (?1, ?2, ?3)",&[&profile.description, &dris_str, &psrs_str]){
        Ok(_) => Ok(handle.last_insert_rowid()),
        Err(E) => Err(E)
    }
}

fn insert_profile_specific_record(handle: Connection, profile_specific_record: &ProfileSpecificRecord) -> Result<i64>{
    match handle.execute("INSERT INTO ProfileSpecificRecord (description, data, data_type) VALUES (?1, ?2, ?3)",&[&profile_specific_record.description, &profile_specific_record.data, &profile_specific_record.data_type]){
        Ok(_) => Ok(handle.last_insert_rowid()),
        Err(E) => Err(E)
    }
}

fn update_profile_specific_record(handle: Connection, profile_specific_record: &ProfileSpecificRecord, id: i64) -> Result<i64>{
    match handle.execute("UPDATE ProfileSpecificRecord SET description = ?1, data = ?2, data_type = ?3) where id = ?4",
                         &[&profile_specific_record.description,
                             &profile_specific_record.data,
                             &profile_specific_record.data_type, &id]){
        Ok(_) => Ok(handle.last_insert_rowid()),
        Err(E) => Err(E)
    }
}

fn update_detail_record(handle: Connection, detail_record: &DetailRecord, id: i64) -> Result<i64>{
    match handle.execute("UPDATE DetailRecord SET description = ?1, data = ?2, data_type = ?3 where id = ?4",
                         &[&detail_record.description,
                             &detail_record.data,
                             &detail_record.data_type, &id]){
        Ok(_) => Ok(handle.last_insert_rowid()),
        Err(E) => Err(E)
    }
}

fn update_details(handle: Connection, details: &Details, id: i64) -> Vec<Result<i32>>{
    let dris = &details.detail_record_ids;
    //Check if the corresponding detailrecord entries are present in DetailRecord table
    handle.execute("DELETE * from Details where id = ?1", &[&id]);
    dris.iter().map(|detail_record| {
        //Break and err if one of the insert fails
        handle.execute("INSERT INTO Details (detail_record_ids) VALUES (?1)",&[&detail_record.id])
    }).collect()
}

fn update_profile(handle: Connection, profile: &Profile, id: i64) -> Result<i64>{
    let dris = &profile.detail_record_ids;
    let psrs = &profile.profile_specific_records;

    let mut dris_str = dris.iter().fold("".to_owned(),|mut dris_str, detail_record| {
        let mut comma_appended = detail_record.id.to_string();
        comma_appended.push_str(",");
        dris_str.push_str(&comma_appended[..]);
        dris_str
    });
    let mut psrs_str = psrs.iter().fold("".to_owned(), |mut psrs_str, psr| {
        let mut comma_appended = psr.id.to_string();
        comma_appended.push_str(",");
        psrs_str.push_str(&comma_appended[..]);
        psrs_str
    });
    match handle.execute("UPDATE SET Profile description = ?1, detail_record_ids = ?2, profile_specific_records = ?3 where id = ?4",&[&profile.description, &dris_str, &psrs_str, &id]){
        Ok(_) => Ok(handle.last_insert_rowid()),
        Err(E) => Err(E)
    }
}


