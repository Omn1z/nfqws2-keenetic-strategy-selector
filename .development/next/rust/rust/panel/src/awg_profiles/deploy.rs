use super::*;

pub(super) async fn active(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        Ok(Json(s.awg_runtime.deploy_profile_with_transport(
            &s.store,
            None,
            s.config.awg_wan_ifaces(),
            |proof| crate::engine::refresh_transport_bypass(&s, proof),
        )))
    })
    .await
}

pub(super) async fn one(
    State(s): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        Ok(Json(s.awg_runtime.deploy_profile_with_transport(
            &s.store,
            Some(&id),
            s.config.awg_wan_ifaces(),
            |proof| crate::engine::refresh_transport_bypass(&s, proof),
        )))
    })
    .await
}

#[derive(Deserialize)]
pub(super) struct Selection {
    #[serde(default)]
    ids: Vec<String>,
}

pub(super) async fn many(
    State(s): State<Shared>,
    ApiJson(v): ApiJson<Selection>,
) -> Result<Json<Value>, ApiError> {
    if v.ids.len() > 128 {
        return Err(ApiError(
            axum::http::StatusCode::BAD_REQUEST,
            "не более 128 серверов за запрос".into(),
        ));
    }
    blocking(move || {
        s.awg_runtime
            .deploy_profiles_with_transport(&s.store, &v.ids, s.config.awg_wan_ifaces(), |proof| {
                crate::engine::refresh_transport_bypass(&s, proof)
            })
            .map(Json)
    })
    .await
}
