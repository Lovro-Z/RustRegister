use std::sync::Arc;

use warp::Filter;

use crate::{handler::Handler, model::{RegisterSubject, RegisterDetails, Details, Subject}};

pub fn with_handler(handler: Arc<Handler>) -> impl Filter<Extract = (Arc<Handler>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || handler.clone())
  }

pub async fn get_subjects_from_register(offset: usize, limit: u64) -> Vec<RegisterSubject> {
  let reqwest_client = reqwest::Client::new();
  println!("offset: {}, limit: {}", offset, limit);
  let result = reqwest_client.get(format!("https://sudreg-api.pravosudje.hr/javni/subjekt/?offset={}&limit={}", offset, limit))
      //use sud_reg_token from env when deployed
      .header("Ocp-Apim-Subscription-Key", "fd2756eee54b4b25b59b586a9185ea3b")
      .send()
      .await
      .expect("failed to get a response")
      .json::<Vec<RegisterSubject>>()
      .await;
  match result {
    Ok(register_subjects) => register_subjects,
    Err(err) => {println!("Error fetching subjects from register, returing empty array... error: {:?}", err); Vec::new()}
  }
}

pub async fn get_subject_details(oib: i64) -> Result<Option<RegisterDetails>, reqwest::Error> {
  let reqwest_client = reqwest::Client::new();
  //test oib: 76860791838
  let temp = reqwest_client.get(format!("https://sudreg-api.pravosudje.hr/javni/subjekt_detalji?tipIdentifikatora=oib&identifikator={}", oib))
    //use sud_reg_token from env when deployed
    .header("Ocp-Apim-Subscription-Key", "fd2756eee54b4b25b59b586a9185ea3b")
    .send()
    .await
    .expect("failed to get a response")
    .json::<Option<RegisterDetails>>()
    .await;
  match temp {
      Ok(val) => {
        match val {
          Some(details) => Ok(Some(details)),
          None =>  Ok(val)
        }
      },
      Err(err) => {println!("Error fetching subject details from register... error: {:?}", err); Err(err)}
  }
}

pub async fn get_new_subjects(db_subjects: &[Subject], register_subjects: &[Subject]) -> Vec<Subject> {
  let mut result: Vec<Subject> = Vec::new();
  for register_subject in register_subjects {
    if !db_subjects.iter().any(|sub| sub.oib == register_subject.oib) {
      result.push(register_subject.clone());
    }
  }
  result
}

pub fn map_details(register_details: RegisterDetails) -> Details {
  Details {
    _id: "".to_string(),
    _rev: "".to_string(),
    mbs: register_details.mbs,
    oib: register_details.oib
  }
}

pub fn map_subjects_from_register(subjects_from_register: &Vec<RegisterSubject>) -> Vec<Subject> {
  let mut result: Vec<Subject> = Vec::new(); 
  for subject in subjects_from_register {
    result.push(Subject {
      _id: "".to_string(),
      _rev: "".to_string(),
      oib: subject.oib
    })
  }
  result
}