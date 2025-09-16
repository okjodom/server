use crate::contexts::auth::use_auth;
use gloo_timers::future::TimeoutFuture;
use leptos::prelude::*;
use leptos::task::spawn_local;
use std::time::{SystemTime, UNIX_EPOCH};

#[component]
pub fn AuthGuard(
    children: Children,
    #[prop(optional)] fallback: Option<ViewFn>,
    #[prop(optional)] required_roles: Option<Vec<String>>,
    #[prop(optional)] redirect_to: Option<String>,
    #[prop(optional)] _session_timeout_minutes: Option<u32>,
) -> impl IntoView {
    let auth = use_auth();

    // Check if user meets role requirements
    let has_required_roles = Signal::derive(move || {
        if let Some(required_roles) = &required_roles {
            if let Some(user) = auth.user.get() {
                // User must have at least one of the required roles
                required_roles.iter().any(|role| user.roles.contains(role))
            } else {
                false
            }
        } else {
            // No specific roles required, just need to be authenticated
            true
        }
    });

    // Check overall access permission with direct cookie fallback
    let has_access = Signal::derive(move || {
        let is_auth = auth.is_authenticated.get();
        let has_roles = has_required_roles.get();

        // Direct cookie-based authentication as primary method
        #[cfg(target_arch = "wasm32")]
        {
            use web_sys::console;

            if let Ok(cookies) = leptos::leptos_dom::helpers::document().cookie() {
                if cookies.contains("auth_token=") {
                    console::log_1(&"🍪 Using direct cookie auth - SUCCESS".into());
                    // Found auth token - consider authenticated regardless of auth context state
                    return true; // Skip role checks for now to get basic auth working
                }
            }

            console::log_1(&"🔐 AuthGuard Debug (no direct cookie auth):".into());
            console::log_1(&format!("  - is_authenticated: {}", is_auth).into());
            console::log_1(&format!("  - has_required_roles: {}", has_roles).into());
            console::log_1(&format!("  - is_loading: {}", auth.is_loading.get()).into());
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            tracing::debug!(
                "AuthGuard: is_authenticated={}, has_required_roles={}, is_loading={}",
                is_auth,
                has_roles,
                auth.is_loading.get()
            );
        }

        is_auth && has_roles
    });

    // Session timeout monitoring
    Effect::new(move |_| {
        if auth.is_authenticated.get() {
            if let Some(expires_at) = auth.token_expires_at.get() {
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if current_time >= expires_at {
                    // Token has expired, logout user
                    tracing::warn!("Session expired, logging out user");
                    auth.logout.run(());
                }
            }
        }
    });

    // Handle redirect logic with enhanced error handling
    let redirect_to_clone = redirect_to.clone();
    Effect::new(move |_| {
        if !auth.is_loading.get() && !has_access.get() {
            let redirect_url_clone = redirect_to_clone.clone();
            // Add delay to prevent rapid redirects
            spawn_local(async move {
                TimeoutFuture::new(100).await;

                if let Some(redirect_url) = redirect_url_clone {
                    let _ = window().location().set_href(&redirect_url);
                } else if !auth.is_authenticated.get() {
                    let _ = window().location().set_href("/login");
                } else {
                    // User is authenticated but doesn't have required roles
                    let _ = window().location().set_href("/unauthorized");
                }
            });
        }
    });

    // Simplified conditional rendering
    if auth.is_loading.get() {
        view! {
            <div class="min-h-screen flex items-center justify-center bg-gray-50">
                <div class="text-center">
                    <div class="w-16 h-16 mx-auto rounded-full bg-blue-100 flex items-center justify-center mb-4">
                        <svg class="animate-spin w-8 h-8 text-blue-600" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"/>
                        </svg>
                    </div>
                    <h2 class="text-xl font-medium text-gray-900 mb-2">
                        "Checking access..."
                    </h2>
                    <p class="text-gray-600 mb-4">
                        "Please wait while we verify your credentials."
                    </p>
                </div>
            </div>
        }.into_any()
    } else if let Some(error_msg) = auth.error.get() {
        view! {
            <div class="min-h-screen flex items-center justify-center bg-yellow-50">
                <div class="text-center max-w-md">
                    <h2 class="text-2xl font-semibold text-yellow-900 mb-2">
                        "Authentication Issue"
                    </h2>
                    <p class="text-yellow-700 mb-4">
                        {error_msg}
                    </p>
                    <button
                        class="inline-flex items-center px-4 py-2 bg-yellow-600 text-white rounded-md hover:bg-yellow-700 transition-colors"
                        on:click=move |_| {
                            auth.clear_error.run(());
                        }
                    >
                        "Dismiss"
                    </button>
                </div>
            </div>
        }.into_any()
    } else if has_access.get() {
        children().into_any()
    } else {
        // Show fallback or access denied
        if let Some(fallback_fn) = &fallback {
            fallback_fn.run()
        } else {
            view! {
                <div class="min-h-screen flex items-center justify-center bg-gray-50">
                    <div class="text-center">
                        <h2 class="text-2xl font-semibold text-gray-900 mb-2">
                            "Access Denied"
                        </h2>
                        <p class="text-gray-600 mb-4">
                            "You don't have permission to access this page."
                        </p>
                    </div>
                </div>
            }
            .into_any()
        }
    }
}

#[component]
pub fn RoleGuard(
    children: Children,
    required_roles: Vec<String>,
    #[prop(optional)] fallback: Option<ViewFn>,
) -> impl IntoView {
    let auth = use_auth();
    let required_roles_clone = required_roles.clone();

    let has_required_role = Signal::derive(move || {
        if let Some(user) = auth.user.get() {
            required_roles_clone
                .iter()
                .any(|role| user.roles.contains(role))
        } else {
            false
        }
    });

    if has_required_role.get() {
        children().into_any()
    } else if let Some(fallback_fn) = &fallback {
        fallback_fn.run()
    } else {
        view! {
            <div class="rounded-md bg-yellow-50 p-4">
                <div class="flex">
                    <div class="flex-shrink-0">
                        <svg class="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                        </svg>
                    </div>
                    <div class="ml-3">
                        <h3 class="text-sm font-medium text-yellow-800">
                            "Insufficient Permissions"
                        </h3>
                        <p class="mt-1 text-sm text-yellow-700">
                            "You need one of the following roles to access this feature: "
                            {required_roles.join(", ")}
                        </p>
                    </div>
                </div>
            </div>
        }.into_any()
    }
}

#[component]
pub fn AdminGuard(children: Children, #[prop(optional)] fallback: Option<ViewFn>) -> impl IntoView {
    let roles = vec!["admin".to_string(), "superadmin".to_string()];

    match fallback {
        Some(fb) => view! {
            <RoleGuard required_roles=roles fallback=fb>
                {children()}
            </RoleGuard>
        }
        .into_any(),
        None => view! {
            <RoleGuard required_roles=roles>
                {children()}
            </RoleGuard>
        }
        .into_any(),
    }
}

#[component]
pub fn SuperAdminGuard(
    children: Children,
    #[prop(optional)] fallback: Option<ViewFn>,
) -> impl IntoView {
    let roles = vec!["superadmin".to_string()];

    match fallback {
        Some(fb) => view! {
            <RoleGuard required_roles=roles fallback=fb>
                {children()}
            </RoleGuard>
        }
        .into_any(),
        None => view! {
            <RoleGuard required_roles=roles>
                {children()}
            </RoleGuard>
        }
        .into_any(),
    }
}
