//! ecrecover-bench command line interface definition.

use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(about = "Ecrecover benchmark")]
pub struct Application {
    #[structopt(short, long, help = "Number of executions", default_value = "10000")]
    pub count: usize,

    #[structopt(
        short,
        long,
        help = "Size of random input buffer",
        default_value = "10000"
    )]
    pub size: usize,
}

/// Constructs an instance of the Application.
pub fn application() -> Application {
    Application::from_args()
}
