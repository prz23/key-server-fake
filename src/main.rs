use key_server_fake::{start_server, Args};

fn main() {
    env_logger::init();
    println!("start key server fake");
    let mut config_server = Args::default();
    config_server.set_port(8000);
    config_server.set_cert_keys("../test-ca/end.fullchain".to_string(), "../test-ca/end.key".to_string());
    start_server(config_server, 200, None);
}