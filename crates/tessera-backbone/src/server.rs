use axum::Router;

pub(super) async fn run() -> anyhow::Result<()> {
    let app = Router::new();
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", 8080)).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
