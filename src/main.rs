#[macro_use] extern crate rocket;

use crate::data::{HashMatcher, Hasher};
use hmac::Mac;
use rocket::yansi::Paint;
use rocket::{Build, Rocket};
use serde::{Deserialize, Serialize};

mod data;
mod database;
mod endpoints;

#[launch]
async fn rocket() -> Rocket<Build> {
    let database_client = database::connect_mongodb()
        .await
        .expect("Failed to initialize MongoDB");

    rocket::build()
        .manage(database::SierraState { database_client })
        .mount("/", routes![endpoints::auth::signup, endpoints::auth::login, endpoints::auth::auth, endpoints::auth::me])
}