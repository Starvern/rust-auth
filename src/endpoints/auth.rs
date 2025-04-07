use std::fs;
use std::time::UNIX_EPOCH;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use mongodb::bson::doc;
use rocket::form::Form;
use rocket::request::{FromRequest, Outcome};
use rocket::serde::{Deserialize, Serialize};
use rocket::serde::json::Json;
use rocket::{Request, State};
use crate::data::{HashMatcher, Hasher, LoginForm, UserPost};
use crate::database;
use crate::database::{UserQueryError, SierraState};

#[derive(Serialize)]
struct AuthResponse {
    token: String,
    message: String
}

#[derive(Serialize, Deserialize, Debug)]
struct UserClaim {
    user: UserPost,
    iss: String,
    exp: u64,
}

fn decode_jwt(token: String) -> Json<AuthResponse> {
    let public_key = fs::read_to_string("public.pem").unwrap();
    let decode_key = DecodingKey::from_rsa_pem(public_key.as_bytes()).unwrap();

    let validation = Validation::new(jsonwebtoken::Algorithm::RS256);

    let decoded_user: Result<TokenData<UserClaim>, _> = decode::<UserClaim>(
        &token,
        &decode_key,
        &validation
    );

    if decoded_user.is_err() {
        println!("decoded: {:#?}", decoded_user);
        return Json(AuthResponse {token: "".to_string(), message: "401 Unauthorized".to_string()});
    }

    let a = decoded_user.unwrap().claims;
    println!("{a:#?}");

    Json(AuthResponse {token: "".to_string(), message: "200 Ok".to_string()})
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for UserClaim {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Success(UserClaim {})
    }
}

#[get("/me")]
pub async fn me(token_data: TokenData<UserClaim>) -> Json<UserPost> {
    Json(token_data.claims.user)
}

#[get("/auth")]
pub async fn auth(user: UserPost) -> Json<AuthResponse> {
    let now_plus_120 = std::time::SystemTime::now()
        .checked_add(core::time::Duration::new(120, 0))
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let claim = UserClaim {
        iss: "localhost".to_string(),
        exp: now_plus_120,
        user
    };

    let private_key = fs::read_to_string("privkey.pem").unwrap();
    let key = EncodingKey::from_rsa_pem(private_key.as_bytes()).unwrap();
    let header = Header::new(jsonwebtoken::Algorithm::RS256);

    let token_str = encode(&header, &claim, &key);

    if token_str.is_err() {
        return Json(AuthResponse {token: "".to_string(), message: token_str.err().unwrap().to_string()});
    }

    Json(AuthResponse {token: token_str.unwrap(), message: "200 Ok".to_string()})
}

#[post("/signup", data = "<user_form_post>")]
pub async fn signup(state: &State<SierraState>, user_form_post: Form<LoginForm>) -> String {
    let resulted_hash = user_form_post.hash().await;

    if resulted_hash.is_err() {
        return "Failed to create user.".to_string();
    }

    let password_hash = resulted_hash.unwrap();

    let insert = state.database_client.database("delta01").collection("charlie01").insert_one(
        doc!{"username": &user_form_post.username, "password": password_hash}
    ).await;

    if insert.is_err() {
        println!("{insert:#?}");
        return "Failed to create user".to_string();
    }

    format!("Created user {}!", &user_form_post.username)
}

#[post("/login", data = "<user_form_post>")]
pub async fn login(state: &State<SierraState>, user_form_post: Form<LoginForm>) -> String {
    let user_post = database::get_user_post(
        &state.database_client,
        &user_form_post.username
    ).await;

    if user_post.is_err() {
        return match &user_post.err().unwrap() {
            UserQueryError::Unknown => "Unknown user".to_string(),
            UserQueryError::Invalid => "Invalid credentials".to_string(),
            UserQueryError::DatabaseError => "Database error".to_string()
        }
    }

    let user = user_post.ok().unwrap();

    if user.matches(&user_form_post.password) {
        format!("Login valid. Use /auth endpoint {}", &user.username)
    }
    else {
        "Invalid credentials.".to_string()
    }
}