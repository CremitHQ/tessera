use tracing_subscriber::fmt::SubscriberBuilder;

#[derive(Default)]
pub(super) struct LoggerConfig {
    pub format: LoggerFormat,
}

#[derive(Default)]
pub(super) enum LoggerFormat {
    #[default]
    Json,
}

pub(super) fn init_logger(config: LoggerConfig) {
    let builder = SubscriberBuilder::default();

    let builder = match config.format {
        LoggerFormat::Json => builder.json(),
    };

    builder.init();
}
