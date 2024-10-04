use tracing_subscriber::fmt::SubscriberBuilder;

#[derive(Default)]
pub(super) struct LoggerConfig {
    pub format: LoggerFormat,
}

pub(super) enum LoggerFormat {
    Json,
}

impl Default for LoggerFormat {
    fn default() -> Self {
        LoggerFormat::Json
    }
}

pub(super) fn init_logger(config: LoggerConfig) {
    let builder = SubscriberBuilder::default();

    let builder = match config.format {
        LoggerFormat::Json => builder.json(),
    };

    builder.init();
}
