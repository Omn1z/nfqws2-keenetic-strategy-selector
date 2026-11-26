use crate::awg_rules::kernel as routes_kernel;
use crate::http::{blocking, ApiError, ApiJson, Shared};
use axum::{
    extract::{Path, Query, State},
    http::header,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::Value;
mod deploy;
mod install;
mod speedtest;
#[cfg(test)]
mod tests;
mod warp;

pub(crate) fn profile_status(s: &Shared) -> std::io::Result<Value> {
    nfqws2_awg_profile::status_with_public_refs(&s.store, &s.awg_runtime, |doc| {
        nfqws2_awg_rules::public_refs(doc)
            .into_iter()
            .map(|reference| (reference.id.clone(), serde_json::json!(reference)))
            .collect()
    })
}

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/awg2", get(status))
        .route("/api/awg2/config", post(save_config))
        .route("/api/awg2/deploy", post(deploy::active))
        .route("/api/awg2/servers/{id}/deploy", post(deploy::one))
        .route("/api/awg2/servers/deploy", post(deploy::many))
        .route("/api/awg2/import", post(import))
        .route("/api/awg2/warp", post(warp::handle))
        .route("/api/awg2/install", post(install::handle))
        .route("/api/awg2/speedtest", post(speedtest::handle))
        .route("/api/awg2/settings/recovery", post(save_recovery))
        .route("/api/awg2/status/refresh", post(refresh))
        .route("/api/awg2/client/up", post(up))
        .route("/api/awg2/client/down", post(down))
        .route("/api/awg2/servers", post(add_server))
        .route("/api/awg2/peers", post(add_peer))
        .route("/api/awg2/peers/{id}", delete(remove_peer))
        .route("/api/awg2/servers/{id}/select", post(select))
        .route("/api/awg2/servers/{id}/test", post(check_connection))
        .route("/api/awg2/servers/{id}", delete(delete_server))
        .route("/api/awg2/servers/{id}/rename", post(rename))
        .route("/api/awg2/servers/{id}/enabled", post(enabled))
        .route("/api/awg2/servers/{id}/endpoint-backups", post(backups))
        .route("/api/awg2/servers/{id}/failover", post(failover))
        .route("/api/awg2/peers/{id}/config", get(export))
}
async fn failover(
    State(s): State<Shared>,
    Path(id): Path<String>,
    ApiJson(policy): ApiJson<nfqws2_awg_profile::Failover>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        let id = id.trim();
        if !routes_kernel::reorder_active_failover(&s, id, &policy)? {
            s.awg_runtime.set_failover_with_transport(
                &s.store,
                id,
                policy,
                s.config.awg_wan_ifaces(),
                |proof| crate::engine::refresh_transport_bypass(&s, proof),
            )?;
        }
        profile_status(&s).map(Json)
    })
    .await
}
async fn check_connection(
    State(s): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    struct Cancellation(Arc<AtomicBool>);
    impl Drop for Cancellation {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let flag = Arc::new(AtomicBool::new(false));
    let _cancel = Cancellation(flag.clone());
    blocking(move || {
        Ok(Json(s.awg_runtime.test_profile_with_transport(
            &s.store,
            &id,
            s.config.awg_wan_ifaces(),
            &flag,
            |proof| crate::engine::refresh_transport_bypass(&s, proof),
        )))
    })
    .await
}
async fn save_config(
    State(s): State<Shared>,
    ApiJson(v): ApiJson<Value>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        let prepared = s.awg_runtime.prepare_routed_endpoint_edit(&s.store, &v)?;
        let warning = routes_kernel::change_profile(&s, || {
            s.awg_runtime.save_config_with_prepared_routed_endpoint(
                &s.store,
                &v,
                s.config.awg_wan_ifaces(),
                prepared.as_ref(),
                |proof| crate::engine::refresh_transport_bypass(&s, proof),
                (
                    |change| routes_kernel::validate_profile_endpoint(&s, change),
                    |change, endpoint| match endpoint {
                        Some(endpoint) => routes_kernel::park_endpoint_retry(&s, change, endpoint),
                        None => routes_kernel::park_profile_mtu(&s, change),
                    },
                ),
            )
        })?;
        if let Some(warning) = warning {
            s.logs.append("awg2", "warn", &warning);
        }
        profile_status(&s).map(Json)
    })
    .await
}
struct Backups {
    endpoint_backups: Option<Vec<Option<String>>>,
}

const ENDPOINT_BACKUPS_REQUIRED: &str =
    "Укажите подключение и список endpoint_backups; для удаления резервных адресов передайте []";

impl<'de> Deserialize<'de> for Backups {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ReadBackups;
        impl<'de> serde::de::Visitor<'de> for ReadBackups {
            type Value = Backups;

            fn expecting(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                out.write_str("an endpoint backups object")
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Backups, E> {
                Ok(Backups {
                    endpoint_backups: None,
                })
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut fields: M,
            ) -> Result<Backups, M::Error> {
                let mut endpoints = None;
                while let Some(field) = fields.next_key::<String>()? {
                    let folded = field.replace('ſ', "s").replace('K', "k");
                    if folded.eq_ignore_ascii_case("endpoint_backups") {
                        endpoints = fields.next_value::<Option<Vec<Option<String>>>>()?;
                    } else {
                        let _: serde::de::IgnoredAny = fields.next_value()?;
                    }
                }
                Ok(Backups {
                    endpoint_backups: endpoints,
                })
            }
        }
        deserializer.deserialize_any(ReadBackups)
    }
}

async fn backups(
    State(s): State<Shared>,
    Path(id): Path<String>,
    ApiJson(v): ApiJson<Backups>,
) -> Result<Json<Value>, ApiError> {
    let id = id.trim().to_owned();
    let endpoints: Vec<_> = v
        .endpoint_backups
        .filter(|_| !id.is_empty())
        .ok_or_else(|| {
            ApiError(
                axum::http::StatusCode::BAD_REQUEST,
                ENDPOINT_BACKUPS_REQUIRED.into(),
            )
        })?
        .into_iter()
        .map(Option::unwrap_or_default)
        .collect();
    blocking(move || {
        let warning = match s.awg_runtime.set_backups_with_transport(
            &s.store,
            &id,
            &endpoints,
            s.config.awg_wan_ifaces(),
            |proof| crate::engine::refresh_transport_bypass(&s, proof),
        ) {
            Ok(warning) => warning,
            Err(error) => {
                let status = if error.get_ref().is_some_and(|e| {
                    e.is::<nfqws2_awg_profile::EndpointBackupsPersistenceUncertain>()
                }) {
                    axum::http::StatusCode::CONFLICT
                } else {
                    axum::http::StatusCode::BAD_REQUEST
                };
                return Ok(Err(ApiError(status, error.to_string())));
            }
        };
        let mut status = profile_status(&s)?;
        if let Some(warning) = warning {
            status["warning"] = Value::String(warning);
        }
        Ok(Ok(Json(status)))
    })
    .await?
}
#[derive(Deserialize)]
struct Replacement {
    replacement_id: Option<String>,
}

pub(crate) fn finish_active_replacement_retirement(s: &Shared) -> std::io::Result<()> {
    use nfqws2_awg_rules::kernel;
    if let Some(launch) = kernel::active_replacement_launch_cleanup(&s.store)? {
        if launch.stop {
            s.awg_runtime.retire_active_replacement(&launch.target)?;
        }
        kernel::finish_active_replacement_launch_cleanup(&s.store, &launch)?;
    }
    if let Some(seal) = kernel::pending_active_replacement_retirement(&s.store)? {
        s.awg_runtime.retire_active_replacement(&seal)?;
        kernel::finish_active_replacement_retirement(&s.store, &seal)?;
    }
    Ok(())
}

fn deleted_connection_ref(doc: &Value, id: &str) -> std::io::Result<Value> {
    let found = nfqws2_awg_rules::public_refs(doc)
        .into_iter()
        .find(|r| r.id == id)
        .ok_or_else(|| std::io::Error::other("публичная идентичность подключения недоступна"))?;
    Ok(serde_json::to_value(found)?)
}

async fn delete_server(
    State(s): State<Shared>,
    Path(id): Path<String>,
    Query(q): Query<Replacement>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        let id = id.trim();
        let replacement = q.replacement_id.as_deref().map(str::trim);
        let dns_replay = std::cell::Cell::new(None);
        let withdraw = match replacement {
            Some(target) if !target.is_empty() && target != id => {
                nfqws2_awg_profile::read(&s.store).and_then(|doc| {
                    if nfqws2_awg_profile::active_replacement_source(&doc, id) {
                        nfqws2_awg_profile::disabled_active_replacement_target(&doc, target)
                            .map(|iface| iface.is_some())
                    } else {
                        Ok(false)
                    }
                })
            }
            _ => Ok(false),
        };
        let lookup = withdraw.as_ref().is_ok_and(|disabled| !disabled);
        let renewed = match replacement {
            Some(target) if lookup && !target.is_empty() && target != id => {
                routes_kernel::prepare_active_replacement_dns(&s, id)
            }
            _ => Ok(None),
        };
        let names = match replacement {
            Some(target) if lookup && !target.is_empty() && target != id => {
                routes_kernel::prepare_profile_replacement_names(&s, id, target)
            }
            _ => Ok(None),
        };
        let removed = routes_kernel::change_profile(&s, || {
            use nfqws2_awg_rules::kernel;
            let renewed = renewed?;
            let names = names?;
            let warm = names.as_ref().and_then(|names| names.warm.as_ref());
            let names = names.as_ref().map(|names| &names.names);
            let withdraw = withdraw?;
            if kernel::active_replacement_in_progress(&s.store)? {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "сначала завершите предыдущий перенос AWG",
                ));
            }
            if let Some(target) = replacement {
                let doc = nfqws2_awg_profile::read(&s.store)?;
                if nfqws2_awg_profile::active_replacement_source(&doc, id) {
                    if nfqws2_awg_profile::disabled_active_replacement_target(&doc, target)?
                        .is_some() != withdraw
                    {
                        return Err(std::io::ErrorKind::Interrupted.into());
                    }
                    let wan = s.config.awg_wan_ifaces();
                    let attempt = routes_kernel::observe_active_replacement(
                        &s,
                        id,
                        renewed.as_ref(),
                        withdraw,
                        warm,
                        |before_write| {
                            if withdraw {
                                return s.awg_runtime.delete_active_profile_with_disabled_target(
                                    &s.store,
                                    id,
                                    target,
                                    wan,
                                    deleted_connection_ref,
                                    |tx, before, after, peers, verify| {
                                        kernel::replace_active_profile_with_disabled_target(
                                            &s.store,
                                            tx,
                                            &nfqws2_router_command::System,
                                            (before, after),
                                            (target, peers, wan),
                                            verify,
                                            || before_write(false),
                                        )
                                    },
                                );
                            }
                            let named_check = |stage: nfqws2_awg_profile::ActiveReplacementStage<'_>| {
                                if let Some(warm) = warm {
                                    warm.verify(&s)?;
                                }
                                kernel::prepare_named_active_replacement_launch(
                                    &s.store,
                                    &nfqws2_router_command::System,
                                    stage,
                                    wan,
                                    names.ok_or(std::io::ErrorKind::InvalidInput)?,
                                )
                            };
                            let preparation = nfqws2_awg_profile::ActiveReplacementPreparation {
                                defer_unresolved_name: names.is_some_and(kernel::NamedActiveReplacement::target_unresolved),
                                check: &|stage| {
                                    kernel::prepare_active_replacement_launch(
                                        &s.store,
                                        &nfqws2_router_command::System,
                                        stage,
                                        wan,
                                        renewed.as_ref().map(|renewed| &renewed.proof),
                                    )
                                },
                                named: names.map(|_| &named_check as &_),
                                defer: &|stage| {
                                    if let Some(names) = &names {
                                        return kernel::defer_named_active_replacement_launch(
                                            &s.store,
                                            &nfqws2_router_command::System,
                                            stage,
                                            wan,
                                            names,
                                            &|| before_write(false),
                                        );
                                    }
                                    kernel::defer_active_replacement_launch(
                                        &s.store,
                                        &nfqws2_router_command::System,
                                        stage,
                                        wan,
                                        &|| before_write(false),
                                    )
                                },
                                refresh: &|proof| {
                                    if let Some(warm) = warm {
                                        warm.verify(&s)?;
                                    }
                                    crate::engine::refresh_transport_bypass(&s, proof)
                                },
                            };
                            if let Some((held, dns)) = renewed.as_ref().and_then(|dns| {
                                dns.proof
                                    .request()
                                    .held_profile()
                                    .map(|held| (held, &dns.proof))
                            }) {
                                return s.awg_runtime.delete_active_profile_with_held_peer(
                                    &s.store,
                                    id,
                                    target,
                                    wan,
                                    deleted_connection_ref,
                                    (held, preparation, |tx, before, after, peers, held| {
                                        kernel::replace_active_profile_with_held_dns(
                                            &s.store,
                                            tx,
                                            &nfqws2_router_command::System,
                                            before,
                                            after,
                                            (peers, held, wan, dns),
                                            || before_write(true),
                                        )
                                    }),
                                );
                            }
                            s.awg_runtime.delete_active_profile_with_standby(
                                &s.store,
                                id,
                                target,
                                wan,
                                deleted_connection_ref,
                                (
                                    preparation,
                                    |tx, before, after, peers| {
                                        if let Some(names) = &names {
                                            if let Some(warm) = warm {
                                                return kernel::replace_active_profile_with_warm_name(
                                                    &s.store,
                                                    tx,
                                                    &nfqws2_router_command::System,
                                                    before,
                                                    after,
                                                    (peers, wan, names, &|| warm.verify_origin(&s)),
                                                    || before_write(true),
                                                );
                                            }
                                            return kernel::replace_active_profile_with_names(
                                                &s.store,
                                                tx,
                                                &nfqws2_router_command::System,
                                                before,
                                                after,
                                                (peers, wan, names),
                                                || before_write(true),
                                            );
                                        }
                                        kernel::replace_active_profile_with_dns(
                                            &s.store,
                                            tx,
                                            &nfqws2_router_command::System,
                                            before,
                                            after,
                                            (
                                                peers,
                                                wan,
                                                renewed.as_ref().map(|renewed| &renewed.proof),
                                            ),
                                            || before_write(true),
                                        )
                                    },
                                ),
                            )
                        },
                    );
                    let cleanup = finish_active_replacement_retirement(&s);
                    if let Err(error) = &cleanup {
                        s.logs.append("awg2", "warn", &error.to_string());
                    }
                    let (mut warning, publication) = attempt?;
                    dns_replay.set(publication);
                    if cleanup.is_err() {
                        let status =
                            "перенос правил сохранён, остановка прежнего AWG будет повторена";
                        warning =
                            Some(warning.map_or_else(
                                || status.to_owned(),
                                |old| format!("{old}. {status}"),
                            ));
                    }
                    s.awg_runtime.invalidate_routing();
                    return Ok(warning);
                }
            }
            let mut reconcile = false;
            let mut warning = s.awg_runtime.delete_profile_with_transport(
                &s.store,
                id,
                replacement,
                deleted_connection_ref,
                |before, after| {
                    let target = replacement.ok_or(std::io::ErrorKind::InvalidInput)?;
                    nfqws2_awg_rules::kernel::stage_dormant_replacement(
                        &s.store,
                        &nfqws2_router_command::System,
                        before,
                        after,
                        id,
                        target,
                    )?;
                    reconcile = true;
                    Ok(())
                },
                (s.config.awg_wan_ifaces(), |proof| {
                    crate::engine::refresh_transport_bypass(&s, proof)
                }),
            )?;
            if reconcile {
                if let Err(error) = nfqws2_awg_rules::kernel::finish_dormant_replacement(&s.store) {
                    s.logs.append("awg2", "warn", &error.to_string());
                    let status = "перенос правил сохранён, подтверждение ревизии будет повторено";
                    warning = Some(
                        warning.map_or_else(|| status.to_owned(), |old| format!("{old}. {status}")),
                    );
                }
                s.awg_runtime.invalidate_routing();
            }
            Ok(warning)
        });
        let warning = match removed {
            Ok(warning) => warning,
            Err(error) if replacement.is_some() => {
                let status = if error.get_ref().is_some_and(|e| {
                    e.is::<nfqws2_awg_profile::DeleteReplacementPersistenceUncertain>()
                }) {
                    axum::http::StatusCode::CONFLICT
                } else {
                    axum::http::StatusCode::BAD_REQUEST
                };
                return Ok(Err(ApiError(status, error.to_string())));
            }
            Err(error) => return Err(error),
        };
        if let Some(publication) = dns_replay.get() {
            s.dnsserver.replay_recent_routes(publication);
        }
        let mut v = profile_status(&s)?;
        if let Some(msg) = warning {
            v["warning"] = serde_json::json!(msg);
        }
        Ok(Ok(Json(v)))
    })
    .await?
}
#[derive(Deserialize)]
struct Enabled {
    enabled: bool,
}
async fn enabled(
    State(s): State<Shared>,
    Path(id): Path<String>,
    ApiJson(v): ApiJson<Enabled>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        if v.enabled {
            routes_kernel::enable_profile(&s, Some(&id), || {
                s.awg_runtime.server_enabled_with_transport(
                    &s.store,
                    &id,
                    true,
                    s.config.awg_wan_ifaces(),
                    |proof| crate::engine::refresh_transport_bypass(&s, proof),
                )
            })?;
        } else {
            routes_kernel::disable_profile(&s, Some(&id))?;
        }
        profile_status(&s).map(Json)
    })
    .await
}
#[derive(Deserialize, Default)]
struct Refresh {
    #[serde(default)]
    trust_on_first_use: bool,
    #[serde(default)]
    server_id: String,
}
async fn refresh(
    State(s): State<Shared>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    let request = if body.is_empty() {
        Refresh::default()
    } else {
        serde_json::from_slice::<Option<Refresh>>(&body)
            .map_err(|e| ApiError(axum::http::StatusCode::BAD_REQUEST, e.to_string()))?
            .unwrap_or_default()
    };
    if request.trust_on_first_use {
        if !s.auth.valid_session(crate::http::token(&headers)) {
            return Err(ApiError(
                axum::http::StatusCode::FORBIDDEN,
                "Войдите в панель, чтобы закрепить первый SSH-ключ".into(),
            ));
        }
        return blocking(move || {
            s.awg_runtime
                .trust_selected_host(&s.store, &request.server_id)
                .map(Json)
        })
        .await;
    }
    blocking(move || s.awg_runtime.refresh_status(&s.store).map(Json)).await
}
async fn save_recovery(
    State(s): State<Shared>,
    ApiJson(v): ApiJson<nfqws2_awg_profile::RecoveryUpdate>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        nfqws2_awg_profile::save_recovery(&s.store, v)?;
        profile_status(&s).map(Json)
    })
    .await
}
async fn client(s: Shared, up: bool) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        let outcome = if up {
            routes_kernel::enable_profile(&s, None, || {
                s.awg_runtime.client_up_with_transport(
                    &s.store,
                    s.config.awg_wan_ifaces(),
                    |proof| crate::engine::refresh_transport_bypass(&s, proof),
                )
            })
        } else {
            routes_kernel::disable_profile(&s, None)
        };
        let action = if up {
            "подключение"
        } else {
            "отключение"
        };
        if let Err(e) = outcome {
            s.logs
                .append("awg2", "warn", &format!("{action} клиента: {e}"));
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                e.to_string(),
            ));
        }
        s.logs
            .append("awg2", "info", &format!("{action} клиента завершено"));
        profile_status(&s).map(Json)
    })
    .await
}
async fn up(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    client(s, true).await
}
async fn down(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    client(s, false).await
}
pub async fn restore(state: &Shared) {
    let s = state.clone();
    if let Err(e) = blocking(move || {
        routes_kernel::change_profile(&s, || {
            s.awg_runtime.restore_clients_with_routing_endpoint_launch(
                &s.store,
                s.config.awg_wan_ifaces(),
                |proof| crate::engine::refresh_transport_bypass(&s, proof),
                |change| routes_kernel::park_profile_mtu(&s, change),
                |change| routes_kernel::pending_endpoint_launch(&s, change),
                |change, endpoint| routes_kernel::park_endpoint_retry(&s, change, endpoint),
            )
        })
    })
    .await
    {
        state
            .logs
            .append("awg2", "warn", &format!("восстановление клиента: {}", e.1));
    }
    let weak = std::sync::Arc::downgrade(state);
    tokio::spawn(async move {
        let mut last_error = String::new();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let Some(s) = weak.upgrade() else {
                break;
            };
            if !s.awg_runtime.has_managed_clients() {
                continue;
            }
            let result = blocking(move || {
                use nfqws2_awg_profile::NamedReconnectInput;
                use nfqws2_awg_rules::kernel::{
                    named_reconnect_revision, validate_named_reconnect,
                };

                let pass = |input| {
                    routes_kernel::retry_profiles(&s, || {
                        s.awg_runtime.recover_clients_with_named_reconnect_policy(
                            &s.store,
                            s.config.awg_wan_ifaces(),
                            |proof| crate::engine::refresh_transport_bypass(&s, proof),
                            (
                                |change| routes_kernel::park_profile_mtu(&s, change),
                                |change| routes_kernel::pending_endpoint_launch(&s, change),
                                |change, endpoint| {
                                    routes_kernel::park_endpoint_retry(&s, change, endpoint)
                                },
                            ),
                            (
                                input,
                                |id, iface, raw| named_reconnect_revision(&s.store, id, iface, raw),
                                |target| {
                                    validate_named_reconnect(
                                        &s.store,
                                        &nfqws2_router_command::System,
                                        target,
                                        s.config.awg_wan_ifaces(),
                                    )
                                },
                                || routes_kernel::named_dns_failure_epoch(&s),
                            ),
                        )
                    })
                };
                let mut first = pass(NamedReconnectInput::Collect)?;
                if !first.named_reconnects.is_empty() {
                    // The first pass released routing and client ownership before DNS.
                    let resolved = first
                        .named_reconnects
                        .into_iter()
                        .map(|request| request.resolve())
                        .collect();
                    first
                        .events
                        .extend(pass(NamedReconnectInput::Apply(resolved))?.events);
                }
                Ok(first.events)
            })
            .await;
            let Some(s) = weak.upgrade() else {
                break;
            };
            match result {
                Ok(events) => {
                    last_error.clear();
                    for item in events {
                        s.logs.append("awg2", "info", &item);
                    }
                }
                Err(e) if e.1 != last_error => {
                    s.logs.append("awg2", "warn", &e.1);
                    last_error = e.1;
                }
                Err(_) => (),
            }
        }
    });
}
pub async fn shutdown(state: &Shared) {
    let s = state.clone();
    if let Err(e) = blocking(move || s.awg_runtime.shutdown_clients()).await {
        state
            .logs
            .append("awg2", "warn", &format!("остановка клиента: {}", e.1));
    }
}
async fn status(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    blocking(move || profile_status(&s).map(Json)).await
}
#[derive(Deserialize)]
struct Import {
    conf: String,
    #[serde(default)]
    name: String,
}
async fn import(
    State(s): State<Shared>,
    ApiJson(v): ApiJson<Import>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        nfqws2_awg_profile::import(&s.store, &v.conf, &v.name)?;
        profile_status(&s).map(Json)
    })
    .await
}
async fn select(State(s): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        nfqws2_awg_profile::select(&s.store, &id)?;
        profile_status(&s).map(Json)
    })
    .await
}
#[derive(Deserialize)]
struct Name {
    name: String,
}

#[derive(Default)]
struct OptionalServerName(String);

impl<'de> Deserialize<'de> for OptionalServerName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ReadName;
        impl<'de> serde::de::Visitor<'de> for ReadName {
            type Value = OptionalServerName;

            fn expecting(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                out.write_str("an optional AWG server name object")
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut fields: M,
            ) -> Result<OptionalServerName, M::Error> {
                let mut name = String::new();
                while let Some(field) = fields.next_key::<String>()? {
                    if field.eq_ignore_ascii_case("name") {
                        if let Value::String(value) = fields.next_value()? {
                            name = value;
                        }
                    } else {
                        let _: serde::de::IgnoredAny = fields.next_value()?;
                    }
                }
                Ok(OptionalServerName(name))
            }
        }
        deserializer.deserialize_map(ReadName)
    }
}

async fn add_server(
    State(s): State<Shared>,
    body: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    let OptionalServerName(name) =
        OptionalServerName::deserialize(&mut serde_json::Deserializer::from_slice(&body))
            .unwrap_or_default();
    blocking(move || {
        nfqws2_awg_profile::add_server(&s.store, &name)?;
        profile_status(&s).map(Json)
    })
    .await
}
async fn add_peer(
    State(s): State<Shared>,
    ApiJson(v): ApiJson<nfqws2_awg_profile::PeerInput>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || Ok(Json(s.awg_runtime.add_profile_peer(&s.store, v)))).await
}
async fn remove_peer(
    State(s): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        s.awg_runtime.remove_profile_peer(&s.store, id)?;
        Ok(Json(serde_json::json!({"status":"ok"})))
    })
    .await
}
async fn rename(
    State(s): State<Shared>,
    Path(id): Path<String>,
    ApiJson(v): ApiJson<Name>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        nfqws2_awg_profile::rename(&s.store, &id, &v.name)?;
        profile_status(&s).map(Json)
    })
    .await
}
#[derive(Default, Deserialize)]
#[serde(default)]
struct Format {
    format: String,
}
async fn export(
    State(s): State<Shared>,
    Path(id): Path<String>,
    Query(q): Query<Format>,
) -> Result<Response, ApiError> {
    let (text, name) =
        blocking(move || nfqws2_awg_profile::peer_export(&s.store, &id, &q.format)).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8".to_owned()),
            (header::CACHE_CONTROL, "no-store".into()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        text,
    )
        .into_response())
}
