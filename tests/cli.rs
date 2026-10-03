// Tests of the portredirect_server and portredirect_client programs: command line, exit codes,
// signals and error messages, which the in-process tests don't cover.

#![cfg(unix)]

use anyhow::{anyhow, Result};
use portredirect::quic::server::load_or_generate_quic_cert;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Duration, Instant};

const SERVER: &str = env!("CARGO_BIN_EXE_portredirect_server");
const CLIENT: &str = env!("CARGO_BIN_EXE_portredirect_client");
const PSK: &str = "cli-test-psk-0123456789";
/// Generous, as the programs may run slowly, e.g. instrumented for coverage.
const WAIT_TIMEOUT: Duration = Duration::from_secs(20);

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind(localhost(0))
        .and_then(|l| l.local_addr())
        .expect("failed to find free TCP port")
        .port()
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind(localhost(0))
        .and_then(|s| s.local_addr())
        .expect("failed to find free UDP port")
        .port()
}

/// A running program whose output is collected in the background.
struct Program {
    child: Child,
    /// stdout and stderr, interleaved by line.
    output: Arc<Mutex<String>>,
    /// stdout alone.
    stdout: Arc<Mutex<String>>,
    output_changed: Arc<Notify>,
    readers: Vec<JoinHandle<()>>,
}

impl Program {
    fn start(program: &str, args: &[&str], env: &[(&str, &str)]) -> Program {
        let mut child = Command::new(program)
            .args(args)
            .env_remove("PORTREDIRECT_PSK")
            .env_remove("PORTREDIRECT_QUIC_PSK")
            .env_remove("RUST_LOG")
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("failed to start program");

        let output = Arc::new(Mutex::new(String::new()));
        let stdout = Arc::new(Mutex::new(String::new()));
        let output_changed = Arc::new(Notify::new());
        let readers = vec![
            collect_output(
                child.stdout.take().unwrap(),
                vec![Arc::clone(&output), Arc::clone(&stdout)],
                &output_changed,
            ),
            collect_output(
                child.stderr.take().unwrap(),
                vec![Arc::clone(&output)],
                &output_changed,
            ),
        ];
        Program {
            child,
            output,
            stdout,
            output_changed,
            readers,
        }
    }

    fn output(&self) -> String {
        self.output.lock().unwrap().clone()
    }

    fn stdout(&self) -> String {
        self.stdout.lock().unwrap().clone()
    }

    /// Waits until the output contains `text`.
    async fn wait_for_output(&self, text: &str) -> Result<()> {
        let found = timeout(WAIT_TIMEOUT, async {
            loop {
                let changed = self.output_changed.notified();
                if self.output().contains(text) {
                    return;
                }
                changed.await;
            }
        })
        .await;
        found.map_err(|_| anyhow!("no {:?} in the output:\n{}", text, self.output()))
    }

    /// Sends SIGTERM, like a service manager stopping the program.
    fn terminate(&self) {
        let pid = self.child.id().expect("the program has exited already");
        let status = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .expect("failed to run kill");
        assert!(status.success(), "kill failed");
    }

    /// Waits until the program exits and returns its exit code.
    async fn exit_code(&mut self) -> Result<i32> {
        let status = timeout(WAIT_TIMEOUT, self.child.wait())
            .await
            .map_err(|_| anyhow!("the program did not exit:\n{}", self.output()))??;
        // Collect the rest of the output.
        for reader in self.readers.drain(..) {
            reader.await?;
        }
        status
            .code()
            .ok_or_else(|| anyhow!("the program was killed by a signal:\n{}", self.output()))
    }
}

/// Appends each line from `pipe` to all `outputs`.
fn collect_output(
    pipe: impl AsyncRead + Unpin + Send + 'static,
    outputs: Vec<Arc<Mutex<String>>>,
    output_changed: &Arc<Notify>,
) -> JoinHandle<()> {
    let output_changed = Arc::clone(output_changed);
    tokio::spawn(async move {
        let mut lines = BufReader::new(pipe).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            for output in &outputs {
                let mut output = output.lock().unwrap();
                output.push_str(&line);
                output.push('\n');
            }
            output_changed.notify_waiters();
        }
    })
}

async fn start_echo_server() -> Result<SocketAddr> {
    let listener = TcpListener::bind(localhost(0)).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
                let _ = write.shutdown().await;
            });
        }
    });
    Ok(addr)
}

/// Sends an HTTP GET request for `path` and returns the whole response.
async fn http_get(addr: SocketAddr, path: &str) -> Result<String> {
    let mut stream = TcpStream::connect(addr).await?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, addr
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = String::new();
    timeout(WAIT_TIMEOUT, stream.read_to_string(&mut response)).await??;
    Ok(response)
}

/// Sends data through the tunnel at `listen_port` and checks that the echo server returns it.
async fn assert_echo(listen_port: u16) -> Result<()> {
    let mut stream = TcpStream::connect(localhost(listen_port)).await?;
    stream.write_all(b"hello").await?;
    let mut echoed = [0u8; 5];
    timeout(WAIT_TIMEOUT, stream.read_exact(&mut echoed)).await??;
    anyhow::ensure!(&echoed == b"hello", "echoed {:?}", echoed);
    Ok(())
}

/// Sends `message` over `stream` and checks that the echo server returns it.
async fn echo_on(stream: &mut TcpStream, message: &[u8]) -> Result<()> {
    stream.write_all(message).await?;
    let mut echoed = vec![0u8; message.len()];
    timeout(WAIT_TIMEOUT, stream.read_exact(&mut echoed)).await??;
    anyhow::ensure!(echoed == message, "echoed {:?}", echoed);
    Ok(())
}

/// Waits until nothing listens on `port` anymore.
async fn wait_until_closed(port: u16) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(localhost(port)).await.is_ok() {
        anyhow::ensure!(Instant::now() < deadline, "port {} is still open", port);
        sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("non-UTF-8 path")
}

/// Starts a server with the PSK in the environment and `extra_args`, and waits until it is
/// ready. It prints its metrics whenever they change.
async fn start_server_with(
    config_dir: &Path,
    quic_port: u16,
    listen_port: u16,
    extra_args: &[&str],
) -> Result<Program> {
    let (listen_port, quic_port) = (listen_port.to_string(), quic_port.to_string());
    let mut args = vec![
        "--config-dir",
        path_str(config_dir),
        "--listen-host",
        "127.0.0.1",
        "--allowed-client-ports",
        &listen_port,
        "--quic-listen-port",
        &quic_port,
        "--quic-cert-hostname",
        "localhost",
        "--print-metrics",
    ];
    args.extend(extra_args);
    let server = Program::start(SERVER, &args, &[("PORTREDIRECT_PSK", PSK)]);
    server.wait_for_output("QUIC server is ready").await?;
    Ok(server)
}

/// Returns the arguments of a client for the server at `quic_port`, without the PSK.
fn client_args(
    config_dir: &Path,
    quic_port: u16,
    destination_port: u16,
    listen_port: u16,
) -> Vec<String> {
    [
        "--config-dir",
        path_str(config_dir),
        "--destination-host",
        "127.0.0.1",
        "--destination-port",
        &destination_port.to_string(),
        "--remote-listen-port",
        &listen_port.to_string(),
        "--quic-remote-host",
        "127.0.0.1",
        "--quic-remote-port",
        &quic_port.to_string(),
        "--quic-cert-hostname",
        "localhost",
    ]
    .map(String::from)
    .to_vec()
}

fn write_psk_file(path: &Path, psk: &str, mode: u32) -> Result<()> {
    fs::write(path, format!("{}\n", psk))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[tokio::test]
async fn invalid_arguments_exit_with_code_2() -> Result<()> {
    let client_with_port_0 = [
        "--destination-host",
        "127.0.0.1",
        "--destination-port",
        "8080",
        "--remote-listen-port",
        "0",
        "--quic-remote-host",
        "127.0.0.1",
        "--quic-remote-port",
        "4433",
        "--psk",
        PSK,
    ];
    let server_with_port_0 = [
        "--listen-host",
        "127.0.0.1",
        "--allowed-client-ports",
        "443,0-100",
        "--psk",
        PSK,
    ];
    let mut client_with_invalid_name = client_with_port_0.to_vec();
    client_with_invalid_name[5] = "443";
    client_with_invalid_name.extend(["--client-name", "my client"]);
    let server_without_psk = [
        "--listen-host",
        "127.0.0.1",
        "--allowed-client-ports",
        "443",
    ];
    // Replaced by --allowed-client-ports.
    let server_with_local_port = [
        "--listen-host",
        "127.0.0.1",
        "--local-port",
        "443",
        "--psk",
        PSK,
    ];

    for (program, args, expected) in [
        (
            CLIENT,
            client_with_port_0.as_slice(),
            "--remote-listen-port",
        ),
        (
            CLIENT,
            client_with_invalid_name.as_slice(),
            "invalid client name \"my client\"",
        ),
        (SERVER, server_with_port_0.as_slice(), "random port"),
        (SERVER, server_without_psk.as_slice(), "--psk"),
        (SERVER, server_with_local_port.as_slice(), "--local-port"),
    ] {
        let mut process = Program::start(program, args, &[]);
        assert_eq!(process.exit_code().await?, 2, "{:?}", args);
        let output = process.output();
        assert!(output.contains(expected), "{:?}:\n{}", args, output);
    }
    Ok(())
}

#[tokio::test]
async fn options_renamed_before_1_0_are_named_with_their_new_names() -> Result<()> {
    for (program, args, env, expected) in [
        (
            SERVER,
            &["--local-host", "127.0.0.1"][..],
            &[][..],
            "--local-host was renamed to --listen-host",
        ),
        (
            SERVER,
            &["--quic-psk-file=/etc/portredirect/psk"],
            &[],
            "--quic-psk-file was renamed to --psk-file",
        ),
        (
            CLIENT,
            &["--quic-remote-hostname-match", "localhost"],
            &[],
            "--quic-remote-hostname-match was renamed to --quic-cert-hostname",
        ),
        (
            CLIENT,
            &[],
            &[("PORTREDIRECT_QUIC_PSK", PSK)],
            "the environment variable PORTREDIRECT_QUIC_PSK was renamed to PORTREDIRECT_PSK",
        ),
    ] {
        let mut process = Program::start(program, args, env);
        assert_eq!(process.exit_code().await?, 2, "{:?}", args);
        let output = process.output();
        assert!(output.contains(expected), "{:?}:\n{}", args, output);
    }
    Ok(())
}

#[tokio::test]
async fn programs_print_their_version() -> Result<()> {
    for (program, name) in [
        (SERVER, "portredirect_server"),
        (CLIENT, "portredirect_client"),
    ] {
        let mut process = Program::start(program, &["--version"], &[]);
        assert_eq!(process.exit_code().await?, 0);
        assert_eq!(
            process.stdout(),
            format!("{} {}\n", name, env!("CARGO_PKG_VERSION"))
        );
    }
    Ok(())
}

#[tokio::test]
async fn logs_go_to_stderr_without_colors_and_follow_rust_log() -> Result<()> {
    // A client without certificate logs a little and exits right away.
    let config_dir = tempfile::tempdir()?;
    let mut args = client_args(config_dir.path(), free_udp_port(), 1, free_tcp_port());
    args.extend(["--psk".into(), PSK.into()]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    let mut client = Program::start(CLIENT, &args, &[]);
    assert_eq!(client.exit_code().await?, 1);
    let output = client.output();
    assert!(output.contains("Configuration directory"), "{}", output);
    // Output to a pipe has no color codes, and stdout stays free for other uses.
    assert!(!output.contains('\x1b'), "{}", output);
    assert_eq!(client.stdout(), "");

    // RUST_LOG takes precedence over --log-level.
    let mut quiet_args = args.clone();
    quiet_args.extend(["--log-level", "trace"]);
    let mut client = Program::start(CLIENT, &quiet_args, &[("RUST_LOG", "error")]);
    assert_eq!(client.exit_code().await?, 1);
    let output = client.output();
    assert!(!output.contains("Configuration directory"), "{}", output);
    assert!(output.contains("copy cert.der"), "{}", output);

    // An invalid RUST_LOG is reported and ignored in favor of --log-level.
    let mut client = Program::start(CLIENT, &quiet_args, &[("RUST_LOG", "portredirect=loud")]);
    assert_eq!(client.exit_code().await?, 1);
    let output = client.output();
    assert!(output.contains("Ignoring invalid RUST_LOG"), "{}", output);
    assert!(output.contains("Configuration directory"), "{}", output);
    assert_eq!(client.stdout(), "");
    Ok(())
}

#[tokio::test]
async fn programs_forward_and_exit_cleanly_on_sigterm() -> Result<()> {
    let (server_dir, client_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await?;

    let server_metrics = localhost(free_tcp_port());
    let mut server = start_server_with(
        server_dir.path(),
        quic_port,
        listen_port,
        &[
            "--provide-metrics",
            "--metrics-listen",
            &server_metrics.to_string(),
        ],
    )
    .await?;
    fs::copy(
        server_dir.path().join("cert.der"),
        client_dir.path().join("cert.der"),
    )?;
    let psk_file = client_dir.path().join("psk");
    write_psk_file(&psk_file, PSK, 0o600)?;

    let metrics_port = free_tcp_port();
    let mut args = client_args(client_dir.path(), quic_port, echo_addr.port(), listen_port);
    args.extend(
        [
            "--psk-file",
            path_str(&psk_file),
            "--provide-metrics",
            "--metrics-listen",
            &localhost(metrics_port).to_string(),
        ]
        .map(String::from),
    );
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut client = Program::start(CLIENT, &args, &[]);
    client.wait_for_output("Tunnel established").await?;

    assert_echo(listen_port).await?;

    // The client's metrics count the tunnel and the forwarded connection, its own only.
    let metrics = http_get(localhost(metrics_port), "/metrics").await?;
    assert!(metrics.starts_with("HTTP/1.1 200 OK"), "{}", metrics);
    for line in [
        "\nportredirect_client_tunnels_total 1\n",
        "\nportredirect_client_tunnel_up 1\n",
        "\nportredirect_client_forwarded_connections_total 1\n",
        "\nportredirect_client_bytes_to_destination_total 5\n",
        "\nportredirect_client_keepalive_failures_total 0\n",
    ] {
        assert!(metrics.contains(line), "no {:?} in:\n{}", line, metrics);
    }
    assert!(!metrics.contains("portredirect_server_"), "{}", metrics);

    // The server's metrics name the client.
    let metrics = http_get(server_metrics, "/metrics").await?;
    for line in [
        "\nportredirect_server_tunnels_active{client=\"default\"} 1\n",
        "\nportredirect_server_forwarded_connections_total{client=\"default\"} 1\n",
        "\nportredirect_server_bytes_from_external_total{client=\"default\"} 5\n",
        "\nportredirect_server_authentication_failures_total 0\n",
    ] {
        assert!(metrics.contains(line), "no {:?} in:\n{}", line, metrics);
    }
    assert!(!metrics.contains("portredirect_client_"), "{}", metrics);

    // The client closes its connection, so the server releases the port right away.
    client.terminate();
    assert_eq!(client.exit_code().await?, 0, "{}", client.output());
    wait_until_closed(listen_port).await?;

    // The server prints its metrics: the tunnel was set up and is down again.
    server
        .wait_for_output("tunnels_active: 0 | tunnels_total: 1")
        .await?;

    server.terminate();
    assert_eq!(server.exit_code().await?, 0, "{}", server.output());
    assert!(server
        .output()
        .contains("PortRedirect Server exited cleanly"));
    // A PSK from the environment or a private file is fine.
    assert!(!client.output().contains("accessible by other users"));
    assert!(!server.output().contains("visible to other local users"));
    Ok(())
}

#[tokio::test]
async fn client_exits_with_code_1_when_the_server_rejects_its_psk() -> Result<()> {
    let (server_dir, client_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());

    // This time with the PSK on the command line.
    let server = Program::start(
        SERVER,
        &[
            "--config-dir",
            path_str(server_dir.path()),
            "--listen-host",
            "127.0.0.1",
            "--allowed-client-ports",
            &listen_port.to_string(),
            "--quic-listen-port",
            &quic_port.to_string(),
            "--quic-cert-hostname",
            "localhost",
            "--psk",
            PSK,
        ],
        &[],
    );
    server.wait_for_output("QUIC server is ready").await?;
    assert!(server.output().contains("visible to other local users"));
    fs::copy(
        server_dir.path().join("cert.der"),
        client_dir.path().join("cert.der"),
    )?;

    // A PSK file other users can read gets a warning.
    let psk_file = client_dir.path().join("psk");
    write_psk_file(&psk_file, "another-psk-0123456789", 0o644)?;
    let mut args = client_args(client_dir.path(), quic_port, 1, listen_port);
    args.extend(["--psk-file".into(), path_str(&psk_file).into()]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut client = Program::start(CLIENT, &args, &[]);

    assert_eq!(client.exit_code().await?, 1, "{}", client.output());
    let output = client.output();
    assert!(
        output.contains("authentication failed (code 1)"),
        "{}",
        output
    );
    assert!(output.contains("accessible by other users"), "{}", output);
    Ok(())
}

#[tokio::test]
async fn client_without_certificate_exits_with_code_1() -> Result<()> {
    let config_dir = tempfile::tempdir()?;
    let mut args = client_args(config_dir.path(), free_udp_port(), 1, free_tcp_port());
    args.extend(["--psk".into(), PSK.into()]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    let mut client = Program::start(CLIENT, &args, &[]);

    assert_eq!(client.exit_code().await?, 1, "{}", client.output());
    assert!(
        client.output().contains("copy cert.der"),
        "{}",
        client.output()
    );
    Ok(())
}

#[tokio::test]
async fn server_does_not_start_without_its_private_key() -> Result<()> {
    let config_dir = tempfile::tempdir()?;
    let key_path = config_dir.path().join("key.der");
    let _ = rustls::crypto::ring::default_provider().install_default();
    load_or_generate_quic_cert(
        "localhost".into(),
        key_path.clone(),
        config_dir.path().join("cert.der"),
    )?;
    fs::remove_file(&key_path)?;

    let mut server = Program::start(
        SERVER,
        &[
            "--config-dir",
            path_str(config_dir.path()),
            "--listen-host",
            "127.0.0.1",
            "--allowed-client-ports",
            "443",
            "--quic-listen-port",
            &free_udp_port().to_string(),
        ],
        &[("PORTREDIRECT_PSK", PSK)],
    );

    assert_eq!(server.exit_code().await?, 1, "{}", server.output());
    assert!(
        server.output().contains("restore the private key"),
        "{}",
        server.output()
    );
    Ok(())
}

#[tokio::test]
async fn server_with_invalid_certificate_name_exits_with_an_error() -> Result<()> {
    let config_dir = tempfile::tempdir()?;

    let mut server = Program::start(
        SERVER,
        &[
            "--config-dir",
            path_str(config_dir.path()),
            "--listen-host",
            "127.0.0.1",
            "--allowed-client-ports",
            "443",
            "--quic-listen-port",
            &free_udp_port().to_string(),
            "--quic-cert-hostname",
            "bücher.example",
        ],
        &[("PORTREDIRECT_PSK", PSK)],
    );

    // An error, not a panic (exit code 101).
    assert_eq!(server.exit_code().await?, 1, "{}", server.output());
    assert!(
        server.output().contains("bücher.example"),
        "{}",
        server.output()
    );
    Ok(())
}

#[tokio::test]
async fn programs_read_configuration_files() -> Result<()> {
    let (server_dir, client_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await?;

    // The server knows two clients, which may both use the port, and one of them is changing its
    // PSK. Paths are relative to the file.
    let home_psk = "home-psk-0123456789";
    let office_next_psk = "office-next-psk-0123456789";
    fs::create_dir(server_dir.path().join("clients"))?;
    for (file, psk) in [
        ("home.psk", home_psk),
        ("office.psk", "office-psk-0123456789"),
        ("office-next.psk", office_next_psk),
    ] {
        write_psk_file(&server_dir.path().join("clients").join(file), psk, 0o600)?;
    }
    let server_config = server_dir.path().join("server.toml");
    fs::write(
        &server_config,
        format!(
            r#"
config-dir = "state"
listen-host = "127.0.0.1"
quic-listen-port = {quic_port}
quic-cert-hostname = "localhost"

[[clients]]
name = "home"
psk-files = ["clients/home.psk"]
ports = {listen_port}

[[clients]]
name = "office"
psk-files = ["clients/office.psk", "clients/office-next.psk"]
ports = [{listen_port}]
"#
        ),
    )?;
    let mut server = Program::start(SERVER, &["--config-file", path_str(&server_config)], &[]);
    server.wait_for_output("QUIC server is ready").await?;
    let standby = format!(
        "Standby is active: clients \"home\" and \"office\" may both use port {}.",
        listen_port
    );
    assert!(server.output().contains(&standby), "{}", server.output());

    // The client already uses the office's next PSK.
    fs::copy(
        server_dir.path().join("state").join("cert.der"),
        client_dir.path().join("cert.der"),
    )?;
    write_psk_file(&client_dir.path().join("psk"), office_next_psk, 0o600)?;
    let client_config = client_dir.path().join("client.toml");
    fs::write(
        &client_config,
        format!(
            r#"
config-dir = "."
destination-host = "127.0.0.1"
destination-port = {}
remote-listen-port = {listen_port}
client-name = "office"
quic-remote-host = "127.0.0.1"
quic-remote-port = {quic_port}
quic-cert-hostname = "localhost"
psk-file = "psk"
log-level = "error"
"#,
            echo_addr.port()
        ),
    )?;

    // The command line takes precedence over the file, so the client logs its progress.
    let client_config = path_str(&client_config);
    let mut office = Program::start(
        CLIENT,
        &["--config-file", client_config, "--log-level", "info"],
        &[],
    );
    office.wait_for_output("Tunnel established").await?;
    assert_echo(listen_port).await?;
    server.wait_for_output("Client \"office\"").await?;
    office.terminate();
    assert_eq!(office.exit_code().await?, 0, "{}", office.output());
    wait_until_closed(listen_port).await?;

    // So does the environment: the other client with its own PSK gets the port.
    let mut home = Program::start(
        CLIENT,
        &[
            "--config-file",
            client_config,
            "--log-level",
            "info",
            "--client-name",
            "home",
        ],
        &[("PORTREDIRECT_PSK", home_psk)],
    );
    home.wait_for_output("Tunnel established").await?;
    assert_echo(listen_port).await?;
    server.wait_for_output("Client \"home\"").await?;
    home.terminate();
    assert_eq!(home.exit_code().await?, 0, "{}", home.output());

    server.terminate();
    assert_eq!(server.exit_code().await?, 0, "{}", server.output());
    Ok(())
}

#[tokio::test]
async fn invalid_configuration_files_exit_with_code_2() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let write = |name: &str, text: &str| -> Result<String> {
        let path = dir.path().join(name);
        fs::write(&path, text)?;
        Ok(path_str(&path).to_string())
    };
    let typo = write(
        "typo.toml",
        "destination-host = \"localhost\"\ndestination-prot = 80\n",
    )?;
    let incomplete = write("incomplete.toml", "destination-host = \"localhost\"\n")?;
    let clients = write(
        "clients.toml",
        "listen-host = \"127.0.0.1\"\n[[clients]]\nname = \"home\"\npsk-files = [\"home.psk\"]\nports = 443\n",
    )?;
    let missing = path_str(&dir.path().join("missing.toml")).to_string();

    for (program, config_file, env, expected) in [
        (CLIENT, &typo, &[][..], "unknown field `destination-prot`"),
        (
            CLIENT,
            &incomplete,
            &[("PORTREDIRECT_PSK", PSK)],
            "--destination-port is required",
        ),
        // A PSK for a single client, though the file lists clients.
        (
            SERVER,
            &clients,
            &[("PORTREDIRECT_PSK", PSK)],
            "PORTREDIRECT_PSK doesn't apply",
        ),
        (
            SERVER,
            &missing,
            &[],
            "failed to read the configuration file",
        ),
    ] {
        let mut process = Program::start(program, &["--config-file", config_file], env);
        assert_eq!(process.exit_code().await?, 2, "{}", config_file);
        let output = process.output();
        assert!(output.contains(expected), "{}:\n{}", config_file, output);
    }
    Ok(())
}

#[tokio::test]
async fn programs_let_running_connections_finish_on_sigterm() -> Result<()> {
    let (server_dir, client_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await?;

    let mut server = start_server_with(
        server_dir.path(),
        quic_port,
        listen_port,
        &["--shutdown-timeout", "60"],
    )
    .await?;
    fs::copy(
        server_dir.path().join("cert.der"),
        client_dir.path().join("cert.der"),
    )?;
    let mut args = client_args(client_dir.path(), quic_port, echo_addr.port(), listen_port);
    args.extend(["--shutdown-timeout".into(), "60".into()]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let env = [("PORTREDIRECT_PSK", PSK)];

    // On SIGTERM, the client stops taking new connections, but lets the running one finish.
    let mut client = Program::start(CLIENT, &args, &env);
    client.wait_for_output("Tunnel established").await?;
    let mut running = TcpStream::connect(localhost(listen_port)).await?;
    echo_on(&mut running, b"before").await?;
    client.terminate();
    wait_until_closed(listen_port).await?;
    echo_on(&mut running, b"during").await?;
    drop(running);
    assert_eq!(client.exit_code().await?, 0, "{}", client.output());
    let output = client.output();
    assert!(
        output.contains("All forwarded connections finished"),
        "{}",
        output
    );

    // A second signal closes running connections right away, here the server's.
    let mut client = Program::start(CLIENT, &args, &env);
    client.wait_for_output("Tunnel established").await?;
    let mut running = TcpStream::connect(localhost(listen_port)).await?;
    echo_on(&mut running, b"before").await?;
    server.terminate();
    server
        .wait_for_output("Waiting up to 60s for running forwarded connections to finish: 1")
        .await?;
    client
        .wait_for_output("The server starts no new forwarded connections")
        .await?;
    echo_on(&mut running, b"during").await?;
    let second_signal = Instant::now();
    server.terminate();
    assert_eq!(server.exit_code().await?, 0, "{}", server.output());
    assert!(second_signal.elapsed() < Duration::from_secs(10));
    let output = server.output();
    assert!(
        output.contains("Closing forwarded connections that didn't finish: 1"),
        "{}",
        output
    );
    // The tunnel ended, so the running connection ended, too.
    let mut buf = [0u8; 16];
    let read = timeout(WAIT_TIMEOUT, running.read(&mut buf)).await?;
    assert!(matches!(read, Ok(0) | Err(_)), "{:?}", read);

    client.terminate();
    assert_eq!(client.exit_code().await?, 0, "{}", client.output());
    Ok(())
}

#[tokio::test]
async fn server_runs_without_its_metrics_endpoint() -> Result<()> {
    let config_dir = tempfile::tempdir()?;
    // Another program uses the metrics port.
    let used = std::net::TcpListener::bind(localhost(0))?;
    let used = used.local_addr()?.to_string();

    let mut server = start_server_with(
        config_dir.path(),
        free_udp_port(),
        free_tcp_port(),
        &["--provide-metrics", "--metrics-listen", &used],
    )
    .await?;
    server
        .wait_for_output("Metrics server failed: failed to bind metrics server")
        .await?;

    // Tunnels matter more than metrics, so the server goes on.
    server.terminate();
    assert_eq!(server.exit_code().await?, 0, "{}", server.output());
    Ok(())
}
