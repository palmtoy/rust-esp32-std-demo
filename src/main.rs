use anyhow::bail;
use log::*;
use std::io::Read;
use std::sync::{Condvar, Mutex};
use std::{env, sync::Arc, thread, time::*};

use embedded_svc::http::server::registry::Registry;
use embedded_svc::http::server::Request;
use embedded_svc::http::server::Response;
use embedded_svc::http::SendStatus;
use embedded_svc::httpd::*;
use embedded_svc::io::adapters::ToStd;
use embedded_svc::wifi::*;

use esp_idf_svc::netif::*;
use esp_idf_svc::nvs::*;
use esp_idf_svc::sysloop::*;
use esp_idf_svc::wifi::*;
use esp_idf_sys::{self};

use esp_idf_hal::ledc::{config::TimerConfig, Channel, Timer};
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_hal::prelude::*;

#[allow(dead_code)]
#[cfg(not(feature = "qemu"))]
const SSID: &str = env!("RUST_ESP32_STD_DEMO_WIFI_SSID");
#[allow(dead_code)]
#[cfg(not(feature = "qemu"))]
const PASS: &str = env!("RUST_ESP32_STD_DEMO_WIFI_PASS");

static mut G_LED_ON: bool = false;

fn main() -> Result<()> {
    esp_idf_sys::link_patches();
    println!("Hello from Rust!");
    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    #[allow(unused)]
    let netif_stack = Arc::new(EspNetifStack::new()?);
    #[allow(unused)]
    let sys_loop_stack = Arc::new(EspSysLoopStack::new()?);
    #[allow(unused)]
    let default_nvs = Arc::new(EspDefaultNvs::new()?);

    #[allow(clippy::redundant_clone)]
    #[cfg(not(feature = "qemu"))]
    #[allow(unused_mut)]
    let mut wifi_obj = conn_to_wifi(
        netif_stack.clone(),
        sys_loop_stack.clone(),
        default_nvs.clone(),
    )?;

    let mutex = Arc::new((Mutex::new(None), Condvar::new()));
    let http_srv = start_http_srv(mutex.clone())?;

    thread::spawn(|| -> anyhow::Result<()> {
        let peripherals = Peripherals::take().unwrap();
        let config = TimerConfig::default().frequency(25.kHz().into());
        let timer = Timer::new(peripherals.ledc.timer0, &config)?;
        let mut channel = Channel::new(peripherals.ledc.channel0, &timer, peripherals.pins.gpio4)?;
        let max_duty = channel.get_max_duty();
        let max_num = 33;
        let duty_interval = 2000 / max_num; // 2s
        loop {
            for numerator in 0..(max_num + 1) {
                unsafe {
                    if !G_LED_ON {
                        channel.set_duty(0)?;
                        break;
                    }
                }
                channel.set_duty(max_duty * numerator / max_num)?;
                thread::sleep(Duration::from_millis(duty_interval.into()));
            }
            for numerator in (0..(max_num + 1)).rev() {
                unsafe {
                    if !G_LED_ON {
                        channel.set_duty(0)?;
                        break;
                    }
                }
                channel.set_duty(max_duty * numerator / max_num)?;
                thread::sleep(Duration::from_millis(duty_interval.into()));
            }
            thread::sleep(Duration::from_millis(500));
        }
    });

    let mut wait = mutex.0.lock().unwrap();

    #[allow(unused)]
    let cycles = loop {
        if let Some(cycles) = *wait {
            break cycles;
        } else {
            wait = mutex
                .1
                .wait_timeout(wait, Duration::from_secs(30))
                .unwrap()
                .0;
        }
    };

    for s in 0..3 {
        info!("Shutting down in {} secs", 3 - s);
        thread::sleep(Duration::from_secs(1));
    }

    drop(http_srv);
    info!("Http server stopped.");

    #[cfg(not(feature = "qemu"))]
    {
        drop(wifi_obj);
        info!("WiFi stopped");
    }

    Ok(())
}

#[allow(unused_variables)]
#[cfg(feature = "experimental")]
fn start_http_srv(
    mutex: Arc<(Mutex<Option<u32>>, Condvar)>,
) -> Result<esp_idf_svc::http::server::EspHttpServer> {
    let mut server = esp_idf_svc::http::server::EspHttpServer::new(&Default::default())?;

    server.handle_get("/", |req, resp| {
        let now = get_cur_time();
        let mut html = html_templated(format!("{} ~ Invalid cmd!", now));
        let query_str = req.query_string();
        println!(
            "{} ~ Got a request path:/ with query string \"{}\"",
            now, query_str
        );
        if query_str == "switch_on" {
            unsafe {
                G_LED_ON = true;
            }
            html = html_templated(format!(
                "{} ~ Switch on and the LED is fading in/out ...",
                now
            ));
        } else if query_str == "switch_off" {
            unsafe {
                G_LED_ON = false;
            }
            html = html_templated(format!("{} ~ Switch off and the LED is also off.", now));
        }
        resp.send_str(&html)?;
        Ok(())
    })?;

    server.handle_post("/wifi_config", |mut req, resp| {
        let now = get_cur_time();
        let mut html = html_templated(format!("{} ~ /wifi_config OK", now));
        let mut buf = Vec::new();
        match ToStd::new(req.reader()).read_to_end(&mut buf) {
            Ok(_) => {}
            Err(e) => {
                warn!("Exception occurs when reading the HTTP buffer!");
            }
        }
        let str_body = match String::from_utf8(buf) {
            Ok(str) => str,
            Err(_) => {
                warn!("Invalid UTF-8 sequence in path:/wifi_config buffer!");
                String::new()
            }
        };
        if str_body.len() <= 0 {
            html = html_templated(format!("{} ~ Invalid params in /wifi_config.", now));
        } else {
            let json_body = match json::parse(str_body.as_str()) {
                Ok(jv) => jv,
                Err(_) => {
                    let err_msg = "Exception occurs when parsing the HTTP body to JSON!";
                    warn!("{}", err_msg);
                    html = html_templated(format!("{} ~ {}", now, err_msg));
                    json::JsonValue::Null
                }
            };
            if json_body != json::JsonValue::Null {
                println!(
                    "{} ~ Got a request path:/wifi_config with body {}: SSID = {}, PWD = {}",
                    now, str_body, json_body["ssid"], json_body["pwd"]
                );
            }
        }
        resp.send_str(&html)?;
        Ok(())
    })?;

    server.handle_get("/foo", |_req, resp| {
        resp.status(500)
            .status_message("Internal Server Error")
            .send_str("Boo, something happened!")?;
        Ok(())
    })?;

    server.handle_get("/bar", |_req, resp| {
        resp.status(403)
            .status_message("No permissions")
            .send_str("You have no permissions to access this page.")?;
        Ok(())
    })?;

    Ok(server)
}

#[cfg(not(feature = "qemu"))]
#[allow(dead_code)]
fn conn_to_wifi(
    netif_stack: Arc<EspNetifStack>,
    sys_loop_stack: Arc<EspSysLoopStack>,
    default_nvs: Arc<EspDefaultNvs>,
) -> Result<Box<EspWifi>> {
    let mut wifi_obj = Box::new(EspWifi::new(netif_stack, sys_loop_stack, default_nvs)?);
    info!("WiFi created, about to scan");
    let ap_infos = wifi_obj.scan()?;
    let ours = ap_infos.into_iter().find(|a| a.ssid == SSID);
    let channel = if let Some(ours) = ours {
        info!(
            "Found configured access point {} on channel {}",
            SSID, ours.channel
        );
        Some(ours.channel)
    } else {
        info!(
            "Configured access point {} not found during scanning, will go with unknown channel",
            SSID
        );
        None
    };

    wifi_obj.set_configuration(&Configuration::Client(ClientConfiguration {
        ssid: SSID.into(),
        password: PASS.into(),
        channel,
        ..Default::default()
    }))?;

    info!("WiFi configuration set, about to get status");

    wifi_obj
        .wait_status_with_timeout(Duration::from_secs(20), |status| !status.is_transitional())
        .map_err(|e| anyhow::anyhow!("Unexpected WiFi status: {:?}", e))?;

    let status = wifi_obj.get_status();

    if let Status(
        ClientStatus::Started(ClientConnectionStatus::Connected(ClientIpStatus::Done(
            _ip_settings,
        ))),
        _,
    ) = status
    {
        info!("WiFi connected");
    } else {
        bail!("Unexpected WiFi status: {:?}", status);
    }

    Ok(wifi_obj)
}

fn html_templated(content: impl AsRef<str>) -> String {
    format!(
        r#"
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <title>esp-rs web server</title>
    </head>
    <body>
        {}
    </body>
</html>
"#,
        content.as_ref()
    )
}

fn get_cur_time() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_secs()
}
