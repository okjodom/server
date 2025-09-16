#[cfg(test)]
mod auth_context_tests {
    use crate::contexts::auth::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_auth_method_display_names() {
        assert_eq!(AuthMethod::Email.display_name(), "Email Address");
        assert_eq!(AuthMethod::Phone.display_name(), "Phone Number");
        assert_eq!(AuthMethod::Pin.display_name(), "PIN Code");
        assert_eq!(AuthMethod::Nostr.display_name(), "Nostr Public Key");
    }

    #[wasm_bindgen_test]
    fn test_auth_method_placeholders() {
        assert_eq!(AuthMethod::Email.placeholder(), "Enter your email address");
        assert_eq!(AuthMethod::Phone.placeholder(), "Enter your phone number");
        assert_eq!(AuthMethod::Pin.placeholder(), "Enter your PIN");
        assert_eq!(AuthMethod::Nostr.placeholder(), "Enter your npub");
    }

    #[wasm_bindgen_test]
    fn test_auth_method_input_types() {
        assert_eq!(AuthMethod::Email.input_type(), "email");
        assert_eq!(AuthMethod::Phone.input_type(), "tel");
        assert_eq!(AuthMethod::Pin.input_type(), "password");
        assert_eq!(AuthMethod::Nostr.input_type(), "text");
    }

    #[ignore] // TODO: Update UserInfo tests to match new structure
    #[wasm_bindgen_test]
    fn test_user_info_full_name() {
        let user_with_both_names = UserInfo {
            user_id: "test-id".to_string(),
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
            given_name: Some("John".to_string()),
            family_name: Some("Doe".to_string()),
            roles: vec![],
            groups: vec![],
        };
        assert_eq!(user_with_both_names.full_name(), "John Doe");

        let user_with_given_only = UserInfo {
            user_id: "test-id".to_string(),
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
            given_name: Some("John".to_string()),
            family_name: None,
            roles: vec![],
            groups: vec![],
        };
        assert_eq!(user_with_given_only.full_name(), "John");

        let user_with_family_only = UserInfo {
            user_id: "test-id".to_string(),
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
            given_name: None,
            family_name: Some("Doe".to_string()),
            roles: vec![],
            groups: vec![],
        };
        assert_eq!(user_with_family_only.full_name(), "Doe");

        let user_with_no_names = UserInfo {
            user_id: "test-id".to_string(),
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
            given_name: None,
            family_name: None,
            roles: vec![],
            groups: vec![],
        };
        assert_eq!(user_with_no_names.full_name(), "testuser");
    }
}

#[cfg(test)]
mod form_validation_tests {
    use crate::hooks::forms::*;

    #[test]
    fn test_validate_required() {
        assert_eq!(
            validate_required("", "Email"),
            Some("Email is required".to_string())
        );
        assert_eq!(
            validate_required("   ", "Email"),
            Some("Email is required".to_string())
        );
        assert_eq!(validate_required("test", "Email"), None);
    }

    #[test]
    fn test_validate_email() {
        // Valid emails
        assert_eq!(validate_email("test@example.com"), None);
        assert_eq!(validate_email("user.name+tag@domain.co.uk"), None);
        assert_eq!(validate_email("test123@subdomain.example.org"), None);

        // Invalid emails
        assert!(validate_email("").is_some());
        assert!(validate_email("invalid").is_some());
        assert!(validate_email("@example.com").is_some());
        assert!(validate_email("test@").is_some());
        assert!(validate_email("test@.com").is_some());

        // Too long email
        let long_email = format!("{}@example.com", "a".repeat(250));
        assert!(validate_email(&long_email).is_some());
    }

    #[test]
    fn test_validate_phone_number() {
        // Valid phone numbers
        assert_eq!(validate_phone_number("1234567890"), None);
        assert_eq!(validate_phone_number("+1 (555) 123-4567"), None);
        assert_eq!(validate_phone_number("555-123-4567"), None);

        // Invalid phone numbers
        assert!(validate_phone_number("").is_some());
        assert!(validate_phone_number("123").is_some()); // Too short
        assert!(validate_phone_number("123456789012345678").is_some()); // Too long
        assert!(validate_phone_number("abc1234567").is_some()); // Contains letters
    }

    #[test]
    fn test_validate_password_strength() {
        // Valid passwords
        assert_eq!(validate_password_strength("Password123!"), None);
        assert_eq!(validate_password_strength("Str0ng@Pass"), None);

        // Invalid passwords
        assert!(validate_password_strength("").is_some()); // Empty
        assert!(validate_password_strength("short").is_some()); // Too short
        assert!(validate_password_strength("password").is_some()); // No uppercase
        assert!(validate_password_strength("PASSWORD").is_some()); // No lowercase
        assert!(validate_password_strength("Password").is_some()); // No digit
        assert!(validate_password_strength("Password123").is_some()); // No special char

        // Too long password
        let long_password = "A".repeat(130) + "1!";
        assert!(validate_password_strength(&long_password).is_some());
    }

    #[test]
    fn test_validate_pin() {
        // Valid PINs
        assert_eq!(validate_pin("1234", 4), None);
        assert_eq!(validate_pin("123456", 4), None);

        // Invalid PINs
        assert!(validate_pin("", 4).is_some()); // Empty
        assert!(validate_pin("123", 4).is_some()); // Too short
        assert!(validate_pin("12ab", 4).is_some()); // Contains letters
    }

    #[test]
    fn test_validate_nostr_pubkey() {
        // Valid Nostr public key (mock format)
        let valid_pubkey = format!("npub{}", "1".repeat(59));
        assert_eq!(validate_nostr_pubkey(&valid_pubkey), None);

        // Invalid public keys
        assert!(validate_nostr_pubkey("").is_some()); // Empty
        assert!(validate_nostr_pubkey("invalid").is_some()); // Doesn't start with npub
        assert!(validate_nostr_pubkey("npub123").is_some()); // Too short
    }

    #[test]
    fn test_validate_password_confirmation() {
        assert_eq!(validate_password_confirmation("password", "password"), None);
        assert!(validate_password_confirmation("password", "").is_some());
        assert!(validate_password_confirmation("password", "different").is_some());
    }

    #[test]
    fn test_validate_min_max_length() {
        assert_eq!(validate_min_length("hello", 3, "Field"), None);
        assert!(validate_min_length("hi", 3, "Field").is_some());

        assert_eq!(validate_max_length("hello", 10, "Field"), None);
        assert!(validate_max_length("this is a very long string", 10, "Field").is_some());
    }
}

#[cfg(test)]
mod session_management_tests {
    use crate::utils::session::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_session_manager_creation() {
        let manager = SessionManager::new(60, 10, 5);
        assert_eq!(manager.session_timeout_minutes, 60);
        assert_eq!(manager.warning_before_expiry_minutes, 10);
        assert_eq!(manager.max_concurrent_sessions, 5);
    }

    #[test]
    fn test_session_expiry_calculation() {
        let manager = SessionManager::new(30, 5, 3);
        let expiry = manager.calculate_expiry_time();
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Should be approximately 30 minutes from now
        let diff = expiry - current;
        assert!(diff >= 1799 && diff <= 1801); // 30 minutes ± 1 second
    }

    #[test]
    fn test_session_expiry_check() {
        let manager = SessionManager::default();
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Future expiry - not expired
        assert!(!manager.is_session_expired(current + 1800));

        // Past expiry - expired
        assert!(manager.is_session_expired(current - 60));

        // Exactly now - expired
        assert!(manager.is_session_expired(current));
    }

    #[test]
    fn test_warning_logic() {
        let manager = SessionManager::new(30, 5, 3);
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Should show warning (3 minutes remaining, warning threshold is 5 minutes)
        let expires_soon = current + 180; // 3 minutes
        assert!(manager.should_show_expiry_warning(expires_soon));

        // Should not show warning (10 minutes remaining)
        let expires_later = current + 600; // 10 minutes
        assert!(!manager.should_show_expiry_warning(expires_later));

        // Already expired - should not show warning
        let expired = current - 60;
        assert!(!manager.should_show_expiry_warning(expired));
    }

    #[test]
    fn test_time_remaining_calculation() {
        let manager = SessionManager::default();
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert_eq!(manager.time_remaining(current + 30), 30);
        assert_eq!(manager.time_remaining(current + 3600), 3600);
        assert!(manager.time_remaining(current - 60) < 0);
    }

    #[test]
    fn test_time_formatting() {
        let manager = SessionManager::default();
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert_eq!(manager.format_time_remaining(current + 30), "30 seconds");
        assert_eq!(manager.format_time_remaining(current + 90), "1 minute");
        assert_eq!(manager.format_time_remaining(current + 150), "2 minutes");
        assert_eq!(manager.format_time_remaining(current + 3600), "1 hour");
        assert_eq!(
            manager.format_time_remaining(current + 3720),
            "1 hour 2 minutes"
        );
        assert_eq!(
            manager.format_time_remaining(current + 7320),
            "2 hours 2 minutes"
        );
        assert_eq!(manager.format_time_remaining(current - 60), "Expired");
    }

    #[test]
    fn test_device_id_generation() {
        let device_id1 = SessionManager::generate_device_id();
        let device_id2 = SessionManager::generate_device_id();

        // Device IDs should start with "dev_"
        assert!(device_id1.starts_with("dev_"));
        assert!(device_id2.starts_with("dev_"));

        // Device IDs should be non-empty beyond the prefix
        assert!(device_id1.len() > 4);
        assert!(device_id2.len() > 4);
    }
}

#[cfg(test)]
mod api_client_tests {
    use crate::utils::enhanced_api::*;

    #[test]
    fn test_api_error_creation() {
        let error = ApiError {
            message: "Test error".to_string(),
            code: Some("TEST_ERROR".to_string()),
            retry_after: Some(60),
        };

        assert_eq!(error.message, "Test error");
        assert_eq!(error.code, Some("TEST_ERROR".to_string()));
        assert_eq!(error.retry_after, Some(60));
        assert_eq!(error.to_string(), "Test error");
    }

    #[test]
    fn test_request_builder_creation() {
        let builder = EnhancedRequestBuilder::new("GET", "https://api.example.com/test");

        assert_eq!(builder.method, "GET");
        assert_eq!(builder.url, "https://api.example.com/test");
        assert!(builder.with_auth);
        assert_eq!(builder.retry_count, 3); // GET requests have 3 retries by default
        assert_eq!(builder.timeout_ms, Some(30000));
        assert!(builder.idempotent); // GET is idempotent
    }

    #[test]
    fn test_request_builder_configuration() {
        let builder = EnhancedRequestBuilder::new("POST", "https://api.example.com/create")
            .without_auth()
            .retry(1)
            .timeout(5000)
            .cache_bust()
            .idempotent(false);

        assert!(!builder.with_auth);
        assert_eq!(builder.retry_count, 1);
        assert_eq!(builder.timeout_ms, Some(5000));
        assert!(builder.cache_bust);
        assert!(!builder.idempotent);
    }

    #[test]
    fn test_error_categorization() {
        let (code, message) = EnhancedRequestBuilder::categorize_error(401, "Unauthorized");
        assert_eq!(code, "UNAUTHORIZED");
        assert_eq!(message, "Your session has expired. Please log in again.");

        let (code, message) = EnhancedRequestBuilder::categorize_error(404, "Not found");
        assert_eq!(code, "NOT_FOUND");
        assert_eq!(message, "The requested resource was not found.");

        let (code, message) =
            EnhancedRequestBuilder::categorize_error(500, "Internal server error");
        assert_eq!(code, "SERVER_ERROR");
        assert_eq!(message, "Internal server error. Please try again later.");
    }
}

#[cfg(test)]
mod integration_tests {
    use crate::contexts::auth::*;
    use crate::hooks::forms::*;
    use crate::utils::session::*;

    #[test]
    fn test_login_credentials_serialization() {
        let creds = LoginCredentials {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };

        let json = serde_json::to_string(&creds).unwrap();
        assert!(json.contains("test@example.com"));
        assert!(json.contains("password123"));

        let deserialized: LoginCredentials = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.email, creds.email);
        assert_eq!(deserialized.password, creds.password);
    }

    #[test]
    fn test_auth_response_deserialization() {
        let json = r#"{
            "access_token": "access123",
            "refresh_token": "refresh456",
            "expires_in": 3600,
            "refresh_expires_in": 7200,
            "token_type": "Bearer",
            "user": {
                "user_id": "user123",
                "email": "test@example.com",
                "username": "testuser",
                "given_name": "Test",
                "family_name": "User",
                "roles": ["user"],
                "groups": ["default"]
            }
        }"#;

        let response: AuthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.access_token, "access123");
        assert_eq!(response.refresh_token, "refresh456");
        assert_eq!(response.expires_in, 3600);
        assert_eq!(response.user.email, "test@example.com");
        assert_eq!(response.user.roles, vec!["user"]);
    }

    #[test]
    fn test_field_config_validation_flow() {
        let email_config = FieldConfig {
            name: "Email".to_string(),
            required: true,
            min_length: Some(5),
            max_length: Some(100),
            pattern: None,
            custom_validator: Some(|value| validate_email(value)),
        };

        // Test valid email
        let valid_result = validate_field("test@example.com", &email_config);
        assert!(valid_result.is_none());

        // Test invalid email
        let invalid_result = validate_field("invalid-email", &email_config);
        assert!(invalid_result.is_some());

        // Test too short
        let short_result = validate_field("a@b", &email_config);
        assert!(short_result.is_some());
    }

    #[test]
    fn test_session_and_auth_integration() {
        let session_manager = SessionManager::new(30, 5, 3);
        let expires_at = session_manager.calculate_expiry_time();

        // Simulate user info that would be stored in auth context
        let user_info = UserInfo {
            user_id: "test-user".to_string(),
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
            given_name: Some("Test".to_string()),
            family_name: Some("User".to_string()),
            roles: vec!["user".to_string()],
            groups: vec!["default".to_string()],
        };

        // Verify session hasn't expired
        assert!(!session_manager.is_session_expired(expires_at));

        // Verify user has expected properties
        assert_eq!(user_info.full_name(), "Test User");
        assert!(user_info.roles.contains(&"user".to_string()));
    }
}

// Helper functions for testing
#[cfg(test)]
#[allow(dead_code)] // TODO: Update test helpers to match new UserInfo structure
pub mod test_helpers {
    use crate::contexts::auth::{AuthResponse, UserInfo};
    use crate::utils::session::SessionManager;

    pub fn create_test_user() -> UserInfo {
        UserInfo {
            id: "test-user-id".to_string(),
            phone: Some("1234567890".to_string()),
            nostr: Some("npub123abc".to_string()),
            roles: vec!["user".to_string()],
            verified: true,
        }
    }

    pub fn create_test_auth_response() -> AuthResponse {
        AuthResponse {
            access_token: Some("test-access-token".to_string()),
            refresh_token: Some("test-refresh-token".to_string()),
            expires_in: Some(3600),
            token_type: Some("Bearer".to_string()),
            user: crate::api::types::user::User {
                id: uuid::Uuid::new_v4(),
                phone: Some(crate::api::types::common::Phone {
                    number: "1234567890".to_string(),
                    country_code: "+1".to_string(),
                }),
                nostr: Some(crate::api::types::common::Nostr {
                    npub: "npub123abc".to_string(),
                }),
                profile: None,
                roles: vec![crate::api::types::common::Role::User],
                verified: true,
                created_at: "2023-01-01T00:00:00Z".to_string(),
                updated_at: "2023-01-01T00:00:00Z".to_string(),
            },
        }
    }

    pub fn create_test_session_manager() -> SessionManager {
        SessionManager::new(30, 5, 3)
    }
}
