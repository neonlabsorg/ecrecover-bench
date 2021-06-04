//! ecrecover-bench command line interface definition.

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(about = "ecrecover benchmark")]
pub struct Application {
    #[structopt(
        short,
        long,
        help = "Number of iterations to call both functions",
        default_value = "10000"
    )]
    pub count: usize,

    #[structopt(
        short,
        long,
        help = "Size of random buffer for keccak256",
        default_value = "10000"
    )]
    pub size: usize,
}

/// Constructs an instance of the Application.
pub fn application() -> Application {
    Application::from_args()
}
