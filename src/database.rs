use mongodb::{Client, Collection};
use mongodb::bson::doc;
use mongodb::options::{ClientOptions, ServerApi, ServerApiVersion};
use crate::data::UserPost;

#[derive(Debug)]
pub enum UserQueryError {
    Unknown,
    Invalid,
    DatabaseError
}

pub struct SierraState {
    pub database_client: Client
}

pub async fn connect_mongodb() -> mongodb::error::Result<Client> {
    let uri = "mongodb+srv://wsierr:wsierr@alpha01.evmmngl.mongodb.net/?retryWrites=true&w=majority&appName=alpha01";
    let mut client_options = ClientOptions::parse(uri).await?;
    let server_api = ServerApi::builder()
        .version(ServerApiVersion::V1)
        .build();
    client_options.server_api = Some(server_api);
    let client = Client::with_options(client_options)?;
    Ok(client)
}

pub async fn get_user_post(client: &Client, username: &String) -> Result<UserPost, UserQueryError> {
    let database = client.database("delta01");
    let collection: Collection<UserPost> = database.collection("charlie01");

    let user_data = collection.find_one(
        doc! {"username": username}
    ).await;

    if user_data.is_err() {
        return Err(UserQueryError::DatabaseError);
    }

    let user_option = user_data.unwrap();

    user_option.ok_or_else(|| UserQueryError::Unknown)
}