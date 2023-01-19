#[cfg(test)]
mod test {
    use crate::utils::{generate_username, setup_environment};
    use common_rust::futures::FutureExt;
    use common_rust::tokio;
    use common_rust::tonic::transport::Channel;
    use common_rust::tracing::info;
    use kp_api::aic::interaction_center_client::InteractionCenterClient;
    use kp_api::aic::{
        AdvocateInfo, Agent, AgentRequest, BasicProfile, ChatChannel, CreateAgentRequest, EmailChannel, Security, UpdateAgentRequest,
        VoiceChannel,
    };
    use std::env;
    use std::panic::AssertUnwindSafe;
    use std::time::Duration;

    const TEST_PREFIX: &str = "taic";

    // test case for create, update and delete AIC user
    #[tokio::test]
    async fn aic_create_update_delete_user_test() {
        setup_environment();
        let id = generate_username(1, TEST_PREFIX);
        info!("starting aic_create_update_delete_user_test with uid: {}", id);

        let agent_request = AgentRequest {
            login_id: id.clone(),
            server_id: "".to_string(),
        };

        let test_result = AssertUnwindSafe(aic_create_update_delete_user_inner(id, agent_request.clone()))
            .catch_unwind()
            .await;

        if test_result.is_err() {
            user_cleanup(agent_request).await;
        }

        assert!(test_result.is_ok());
    }

    // test case for create, update and delete AIC user with LRM_ID
    #[tokio::test]
    async fn aic_create_update_delete_user_lrm_test() {
        setup_environment();
        let id = generate_username(2, TEST_PREFIX);
        info!("starting aic_create_update_delete_user_lrm_test with uid: {}", id);

        let agent_request = AgentRequest {
            login_id: id.clone(),
            server_id: "".to_string(),
        };

        let test_result = AssertUnwindSafe(aic_create_update_delete_user_lrm_inner(id, agent_request.clone()))
            .catch_unwind()
            .await;

        if test_result.is_err() {
            user_cleanup(agent_request).await;
        }

        assert!(test_result.is_ok());
    }

    async fn aic_create_update_delete_user_inner(id: String, agent_request: AgentRequest) -> Result<(), Box<dyn std::error::Error>> {
        let agent = get_client().await.get_agent(agent_request.clone()).await;
        if agent.is_ok() {
            // update AIC user
            info!("starting aic_update_user with uid: {}", id);
            let update_start = std::time::Instant::now();
            let mut updated_agent = get_agent(&id.clone());
            let mut basic_profile = updated_agent.basic_profile.unwrap();
            basic_profile.first_name = "updatedJoe".to_string();
            updated_agent.basic_profile = Some(basic_profile);
            let request = UpdateAgentRequest {
                agent: Some(updated_agent),
            };
            let result = get_client().await.update_agent(request).await;

            assert!(result.is_ok());

            validate_agent(agent_request.clone(), id.clone(), "updatedJoe".to_string(), "".to_string()).await;
            info!(
                "finished aic_update_user with uid: {}, took {}s",
                id,
                update_start.elapsed().as_secs_f64()
            );
        } else {
            // create AIC user
            info!("starting aic_create_user with uid: {}", id);
            let create_start = std::time::Instant::now();
            let agent = get_agent(&id);
            let request = CreateAgentRequest { agent: Some(agent) };
            let result = get_client().await.create_agent(request).await;

            assert!(result.is_ok());
            validate_agent(agent_request.clone(), id.clone(), "Joe".to_string(), "".to_string()).await;
            info!(
                "finished aic_create_user with uid: {}, took {}s",
                id,
                create_start.elapsed().as_secs_f64()
            );

            // update AIC user
            info!("starting aic_update_user with uid: {}", id);
            let update_start = std::time::Instant::now();
            let mut updated_agent = get_agent(&id);
            let mut basic_profile = updated_agent.basic_profile.unwrap();
            basic_profile.first_name = "updatedJoe".to_string();
            updated_agent.basic_profile = Some(basic_profile);
            let request = UpdateAgentRequest {
                agent: Some(updated_agent),
            };
            let result1 = get_client().await.update_agent(request).await;

            assert!(result1.is_ok());
            validate_agent(agent_request.clone(), id.clone(), "updatedJoe".to_string(), "".to_string()).await;
            info!(
                "finished aic_update_user with uid: {}, took {}s",
                id,
                update_start.elapsed().as_secs_f64()
            );
        }

        // delete AIC user
        info!("starting aic_delete_user with uid: {}", id);
        let delete_start = std::time::Instant::now();
        let result = get_client().await.delete_agent(agent_request).await;
        assert!(result.is_ok());
        info!(
            "finished aic_delete_user with uid: {}, took {}s",
            id,
            delete_start.elapsed().as_secs_f64()
        );
        Ok(())
    }

    async fn aic_create_update_delete_user_lrm_inner(id: String, agent_request: AgentRequest) -> Result<(), Box<dyn std::error::Error>> {
        let agent = get_client().await.get_agent(agent_request.clone()).await;
        if agent.is_ok() {
            // update AIC user
            info!("starting aic_update_user with uid: {}", id);
            let update_start = std::time::Instant::now();
            let mut updated_agent = get_agent(&id.clone());
            let mut basic_profile = updated_agent.basic_profile.unwrap();
            basic_profile.first_name = "updatedJoe".to_string();
            updated_agent.basic_profile = Some(basic_profile);
            let mut advocate_info = updated_agent.advocate_info.clone().unwrap();
            advocate_info.enabled = true;
            advocate_info.lrm_id = "DefaultLRM".to_string();
            updated_agent.advocate_info = Some(advocate_info);
            let request = UpdateAgentRequest {
                agent: Some(updated_agent),
            };
            let result = get_client().await.update_agent(request).await;

            assert!(result.is_ok());
            validate_agent(
                agent_request.clone(),
                id.clone(),
                "updatedJoe".to_string(),
                "DefaultLRM".to_string(),
            )
                .await;
            info!(
                "finished aic_update_user with uid: {}, took {}s",
                id,
                update_start.elapsed().as_secs_f64()
            );
        } else {
            // create AIC user
            info!("starting aic_create_user with uid: {}", id);
            let create_start = std::time::Instant::now();
            let mut agent = get_agent(&id);
            let mut advocate_info = agent.advocate_info.clone().unwrap();
            advocate_info.enabled = true;
            let lrm_id = env::var("AIC_LRMID").unwrap_or_default();
            if lrm_id.is_empty() {
                advocate_info.lrm_id = "DefaultLRM".to_string();
            } else {
                advocate_info.lrm_id = lrm_id;
            }

            agent.advocate_info = Some(advocate_info);
            let request = CreateAgentRequest { agent: Some(agent) };
            let result = get_client().await.create_agent(request).await;

            assert!(result.is_ok());
            validate_agent(agent_request.clone(), id.clone(), "Joe".to_string(), "DefaultLRM".to_string()).await;
            info!(
                "finished aic_create_user with uid: {}, took {}s",
                id,
                create_start.elapsed().as_secs_f64()
            );

            // update AIC user
            let update_start = std::time::Instant::now();
            info!("starting aic_update_user with uid: {}", id);
            let mut updated_agent = get_agent(&id);
            let mut basic_profile = updated_agent.basic_profile.unwrap();
            basic_profile.first_name = "updatedJoe".to_string();
            updated_agent.basic_profile = Some(basic_profile);
            let mut advocate_info = updated_agent.advocate_info.clone().unwrap();
            advocate_info.enabled = true;
            let lrm_id = env::var("AIC_LRMID").unwrap_or_default();
            if lrm_id.is_empty() {
                advocate_info.lrm_id = "DefaultLRM".to_string();
            } else {
                advocate_info.lrm_id = lrm_id;
            }
            updated_agent.advocate_info = Some(advocate_info);
            let request = UpdateAgentRequest {
                agent: Some(updated_agent),
            };
            let result1 = get_client().await.update_agent(request).await;

            assert!(result1.is_ok());
            validate_agent(
                agent_request.clone(),
                id.clone(),
                "updatedJoe".to_string(),
                "DefaultLRM".to_string(),
            )
                .await;
            info!(
                "finished aic_update_user with uid: {}, took {}s",
                id,
                update_start.elapsed().as_secs_f64()
            );
        }

        // delete AIC user
        info!("starting aic_delete_user with uid: {}", id);
        let delete_start = std::time::Instant::now();
        let result = get_client().await.delete_agent(agent_request).await;
        assert!(result.is_ok());
        info!(
            "finished aic_delete_user with uid: {}, took {}s",
            id,
            delete_start.elapsed().as_secs_f64()
        );
        Ok(())
    }

    // cleanup function should never panic
    async fn user_cleanup(agent_request: AgentRequest) {
        get_client().await.delete_agent(agent_request).await.ok();
    }

    async fn validate_agent(agent_request: AgentRequest, id: String, first_name: String, lrm_id: String) {
        let agent = get_client().await.get_agent(agent_request.clone()).await.unwrap().into_inner();
        assert_eq!(agent.login_id, id);
        assert_eq!(agent.basic_profile.unwrap().first_name, first_name);
        assert_eq!(agent.advocate_info.unwrap().lrm_id, lrm_id);
    }

    async fn get_client() -> InteractionCenterClient<Channel> {
        fn grpc_url(service: &str) -> String {
            format!("http://{}:{}", service, 50055)
        }

        let channel = Channel::from_shared(grpc_url("aic-service"))
            .unwrap()
            .timeout(Duration::from_secs(5))
            .connect()
            .await
            .unwrap();

        InteractionCenterClient::new(channel)
    }

    fn get_agent(id: &str) -> Agent {
        Agent {
            advocate_info: Some(AdvocateInfo {
                lrm_id: "".to_string(),
                enabled: false,
            }),
            basic_profile: Some(BasicProfile {
                domain: env::var("AIC_DOMAIN").unwrap_or_default(),
                first_name: "Joe".to_string(),
                last_name: "Doe".to_string(),
                preferred_name: "Joe".to_string(),
                site: env::var("AIC_SITE").unwrap_or_default(),
                work_groups: vec![env::var("AIC_WORKGROUPS").unwrap_or_default()],
                middle_name: "".to_string(),
            }),
            voice_channel: Some(VoiceChannel {
                enabled: true,
                task_ceiling: Some(1),
                task_load: Some(1),
                password: Some(env::var("TESTS_AIC_PASSWORD").unwrap_or_default()),
                phone_id: Some(id.to_string()),
                phone_type: Some(env::var("TESTS_AIC_PHONE_TYPE").unwrap_or_default()),
                queue: None,
            }),
            email_channel: Some(EmailChannel {
                enabled: false,
                task_ceiling: None,
                task_load: None,
                from_address: None,
            }),
            chat_channel: Some(ChatChannel {
                enabled: false,
                task_ceiling: None,
                task_load: None,
            }),
            login_id: id.to_string(),
            security: Some(Security {
                disable_login: false,
                force_pwd_change: false,
                password: env::var("TESTS_AIC_PASSWORD").unwrap_or_default(),
                role_agent: true,
            }),
            task_ceiling: 1,
            task_load: 1,
            server_id: "".to_string(),
        }
    }
}