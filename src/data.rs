use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use mongodb::bson::oid::ObjectId;
use rocket::serde::{Deserialize, Serialize};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rocket::http::Status;
use rocket::{Request};
use rocket::futures::StreamExt;
use rocket::request::{FromRequest, Outcome};
use crate::database::{get_user_post, SierraState};

#[derive(FromForm)]
pub struct LoginForm {
    pub username: String,
    pub password: String
}

pub trait Hasher {
    async fn hash(&self) -> Result<String, argon2::password_hash::Error>;
}

impl Hasher for LoginForm {
    async fn hash(&self) -> Result<String, argon2::password_hash::Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        Ok(argon2.hash_password(self.password.as_bytes(), &salt)?.to_string())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserPost {
    pub _id: ObjectId,
    pub username: String,
    pub password: String
}

pub trait HashMatcher {
    fn matches(&self, hashed_password: &String) -> bool;
}

impl HashMatcher for UserPost {
    fn matches(&self, hashed_password: &String) -> bool {
        let parsed_hash = PasswordHash::new(&self.password);

        if parsed_hash.is_err() {
            println!("{:#?}", parsed_hash);
            return false;
        }

        Argon2::default().verify_password(hashed_password.as_bytes(), &parsed_hash.unwrap()).is_ok()
    }
}

#[derive(Default, Debug)]
pub struct User {
    pub _id: ObjectId,
    pub username: String
}

#[derive(Debug)]
pub enum ApiAccessError {
    Missing,
    Invalid,
    Unknown,
    DatabaseError
}

pub struct BasicAuthHeaders<'a> {
    pub username: &'a String,
    pub password: &'a String
}

#[rocket::async_trait]
impl <'r> FromRequest<'r> for UserPost {
    type Error = ApiAccessError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();

        let username = headers.get_one("username");
        let password = headers.get_one("password");

        if username.is_none() || password.is_none() {
            return Outcome::Error((Status::Unauthorized, ApiAccessError::Missing));
        }

        let option_state: Option<&SierraState> = request.rocket().state::<SierraState>();

        if option_state.is_none() {
            return Outcome::Error((Status::Unauthorized, ApiAccessError::DatabaseError));
        }

        let state = option_state.unwrap();

        let user_post_option = get_user_post(
            &state.database_client, &String::from(username.unwrap())
        ).await;

        if user_post_option.is_err() {
            return Outcome::Error((Status::Unauthorized, ApiAccessError::Unknown));
        }

        let user_post = user_post_option.unwrap();

        let matches = &user_post.matches(&password.unwrap().to_string());

        if *matches {
            return Outcome::Success(user_post)
        }

        Outcome::Error((Status::Unauthorized, ApiAccessError::Invalid))
    }
}
