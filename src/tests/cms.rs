#[cfg(test)]
mod test {
    use crate::utils::{generate_username, setup_environment};
    use common_rust::chrono::{Datelike, Utc};
    use common_rust::futures::FutureExt;
    use common_rust::tokio;
    use common_rust::tonic::transport::Channel;
    use common_rust::tracing::info;
    use kp_api::cms::cms_client::CmsClient;
    use kp_api::cms::{DeleteUserRequest, GetUserRequest, ProvisionUserRequest, User, UserId};
    use std::env;
    use std::panic::AssertUnwindSafe;
    use std::time::Duration;
    use tokio::time::sleep;

    const TEST_PREFIX: &str = "tcms";
    const FIVE_SECONDS: Duration = Duration::from_secs(5);

    // test case for create, update and delete CMS agent user
    #[tokio::test]
    async fn cms_create_update_delete_agent_test() {
        setup_environment();
        let id = generate_username(1, TEST_PREFIX);
        info!("starting cms_create_update_delete_agent_test with uid: {}", id);

        let user = get_user(&id.clone());
        let user_id = UserId {
            id: id.clone(),
            server_id: Some("".to_string()),
        };

        let test_result = AssertUnwindSafe(cms_create_update_delete_agent_inner(&id, user, user_id.clone()))
            .catch_unwind()
            .await;

        if test_result.is_err() {
            user_cleanup(user_id).await;
        }

        assert!(test_result.is_ok());
    }

    // test case for create, update and delete CMS supervisor user
    #[tokio::test]
    async fn cms_create_update_delete_supervisor_test() {
        setup_environment();
        sleep(FIVE_SECONDS).await;
        let id = generate_username(2, TEST_PREFIX);
        info!("starting cms_create_update_delete_supervisor_test with uid: {}", id);

        let user = get_user(&id.clone());
        let user_id = UserId {
            id: id.clone(),
            server_id: Some("".to_string()),
        };

        let test_result = AssertUnwindSafe(cms_create_update_delete_supervisor_inner(&id, user, user_id.clone()))
            .catch_unwind()
            .await;

        if test_result.is_err() {
            user_cleanup(user_id).await;
        }

        assert!(test_result.is_ok());
    }

    async fn cms_create_update_delete_agent_inner(id: &str, mut user: User, user_id: UserId) -> Result<(), Box<dyn std::error::Error>> {
        // create CMS agent user
        info!("starting cms_create_agent_user with uid: {}", id);
        let create_start = std::time::Instant::now();
        let request = ProvisionUserRequest { user: Some(user.clone()) };
        let result = get_client().await.provision_user(request).await;
        if result.as_ref().is_err() {
            info!("error occurred during cms_create_agent_user: {:?}", result.as_ref().err());
        }
        assert!(result.is_ok());
        validate_agent(user.clone(), format_uid(), "Joe Doe".to_string()).await;
        info!(
            "finished cms_create_agent_user with uid: {}, took {}s",
            id,
            create_start.elapsed().as_secs_f64()
        );

        // update CMS agent user
        info!("starting cms_update_agent_user with uid: {}", id);
        let update_start = std::time::Instant::now();
        user.name = "Joe Doe1".to_string();
        let request1 = ProvisionUserRequest { user: Some(user.clone()) };
        let result1 = get_client().await.provision_user(request1).await;
        if result1.as_ref().is_err() {
            info!("error occurred during cms_update_agent_user: {:?}", result1.as_ref().err());
        }
        assert!(result1.is_ok());
        validate_agent(user.clone(), format_uid(), "Joe Doe1".to_string()).await;
        info!(
            "finished cms_update_agent_user with uid: {}, took {}s",
            id,
            update_start.elapsed().as_secs_f64()
        );

        // delete CMS agent user
        info!("starting cms_delete_agent_user with uid: {}", id);
        let delete_start = std::time::Instant::now();
        let request = DeleteUserRequest {
            id: user_id.id,
            server_id: user_id.server_id,
        };
        let result2 = get_client().await.delete_user(request).await;
        if result2.as_ref().is_err() {
            info!("error occurred during cms_delete_agent_user: {:?}", result2.as_ref().err());
        }
        assert!(result2.is_ok());
        info!(
            "finished cms_delete_agent_user with uid: {}, took {}s",
            id,
            delete_start.elapsed().as_secs_f64()
        );

        Ok(())
    }

    async fn cms_create_update_delete_supervisor_inner(
        id: &str,
        mut user: User,
        user_id: UserId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // create CMS supervisor user
        info!("starting cms_create_supervisor_user with uid: {}", id);
        let create_start = std::time::Instant::now();
        user.user = true;
        let request3 = ProvisionUserRequest { user: Some(user.clone()) };
        let result3 = get_client().await.provision_user(request3).await;
        if result3.as_ref().is_err() {
            info!("error occurred during cms_create_supervisor_user: {:?}", result3.as_ref().err());
        }
        assert!(result3.is_ok());
        validate_agent(user.clone(), format_uid(), "Joe Doe".to_string()).await;
        validate_user(user_id.clone(), format_uid(), "Joe Doe".to_string()).await;
        info!(
            "finished cms_create_supervisor_user with uid: {}, took {}s",
            id,
            create_start.elapsed().as_secs_f64()
        );

        // update CMS supervisor user
        info!("starting cms_update_supervisor_user with uid: {}", id);
        let update_start = std::time::Instant::now();
        user.name = "Joe Doe1".to_string();
        user.user = true;
        let request4 = ProvisionUserRequest { user: Some(user.clone()) };
        let result4 = get_client().await.provision_user(request4).await;
        if result4.as_ref().is_err() {
            info!("error occurred during cms_update_supervisor_user: {:?}", result4.as_ref().err());
        }
        assert!(result4.is_ok());
        validate_agent(user.clone(), format_uid(), "Joe Doe1".to_string()).await;
        validate_user(user_id.clone(), format_uid(), "Joe Doe1".to_string()).await;
        info!(
            "finished cms_update_supervisor_user with uid: {}, took {}s",
            id,
            update_start.elapsed().as_secs_f64()
        );

        // delete CMS supervisor user
        info!("starting cms_delete_supervisor_user with uid: {}", id);
        let delete_start = std::time::Instant::now();
        let request = DeleteUserRequest {
            id: user_id.id,
            server_id: user_id.server_id,
        };
        let result5 = get_client().await.delete_user(request).await;
        if result5.as_ref().is_err() {
            info!("error occurred during cms_delete_supervisor_user: {:?}", result5.as_ref().err());
        }
        assert!(result5.is_ok());
        info!(
            "finished cms_delete_supervisor_user with uid: {}, took {}s",
            id,
            delete_start.elapsed().as_secs_f64()
        );

        Ok(())
    }

    // cleanup function should never panic
    async fn user_cleanup(user_id: UserId) {
        let request = DeleteUserRequest {
            id: user_id.id,
            server_id: user_id.server_id,
        };
        get_client().await.delete_user(request).await.ok();
    }

    async fn validate_agent(user: User, uid: String, name: String) {
        let agent = get_client().await.get_agent(user).await.unwrap().into_inner();
        assert_eq!(
            agent.login_id.to_string(),
            uid.clone().strip_prefix('t').unwrap_or_default().to_string()
        );
        assert_eq!(agent.agent_name, name);
    }

    async fn validate_user(user_id: UserId, uid: String, name: String) {
        let request = GetUserRequest {
            id: user_id.id,
            server_id: user_id.server_id,
        };
        let user = get_client().await.get_user(request).await.unwrap().into_inner();
        assert_eq!(user.uid, uid);
        assert_eq!(user.name, name);
    }

    fn format_uid() -> String {
        let datetime = Utc::now();
        let uid = format!("t{:04}{:02}{:02}", datetime.year(), datetime.month(), datetime.day());
        uid
    }

    async fn get_client() -> CmsClient<Channel> {
        fn grpc_url(service: &str) -> String {
            format!("http://{}:{}", service, 50055)
        }

        let channel = Channel::from_shared(grpc_url("cms-service"))
            .unwrap()
            .timeout(Duration::from_secs(5))
            .connect()
            .await
            .unwrap();

        CmsClient::new(channel)
    }

    fn get_user(id: &str) -> User {
        User {
            uid: id.to_string(),
            name: "Joe Doe".to_string(),
            room_number: "".to_string(),
            telephone_number: "".to_string(),
            printer_name: "".to_string(),
            user_type: 0,
            max_window_count: env::var("CMS_MAX_WINDOW_COUNT")
                .unwrap_or_default()
                .parse::<i32>()
                .unwrap_or_default(),
            min_refresh_rate: env::var("CMS_MIN_REFRESH_RATE")
                .unwrap_or_default()
                .parse::<i32>()
                .unwrap_or_default(),
            login_acd: env::var("CMS_LOGIN_ACD").unwrap_or_default(),
            server_id: "".to_string(),
            password: "".to_string(),
            agent: true,
            user: false,
        }
    }
}