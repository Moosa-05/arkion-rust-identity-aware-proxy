use crate::authz::engine::{Decision, PolicyEngine};
use crate::middleware::request_context::RequestContext;
use axum::{
    extract::{Extension, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use std::sync::Arc;

pub async fn authorization_middleware(
    Extension(engine): Extension<Arc<PolicyEngine>>,
    mut req: Request,
    next: Next,
) -> Response {
    let (identity_str, method, path) = if let Some(ctx) = req.extensions().get::<RequestContext>() {
        (
            ctx.identity.identity.clone(),
            ctx.method.clone(),
            ctx.uri_path.clone(),
        )
    } else {
        (
            "anonymous".to_string(),
            req.method().to_string(),
            req.uri().path().to_string(),
        )
    };

    let decision = engine.evaluate(&identity_str, &method, &path);

    if let Some(ctx) = req.extensions_mut().get_mut::<RequestContext>() {
        ctx.decision = decision.as_str().to_string();
    }

    match decision {
        Decision::Allow => next.run(req).await,
        Decision::Deny => {
            tracing::warn!(
                "Authorization DENIED for identity='{}' requesting {} {}",
                identity_str,
                method,
                path
            );

            let body = json!({
                "error": "Forbidden",
                "message": format!("Identity '{}' is not authorized to perform {} {}", identity_str, method, path),
                "identity": identity_str
            });

            (StatusCode::FORBIDDEN, Json(body)).into_response()
        }
    }
}
