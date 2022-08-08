use log::*;
use anyhow::bail;
use std::sync::{Condvar, Mutex};
use std::{env, sync::Arc, thread, time::*};

use embedded_svc::wifi::*;
use embedded_svc::httpd::*;
use embedded_svc::httpd::registry::Registry;

use esp_idf_sys::{self};
use esp_idf_svc::nvs::*;
use esp_idf_svc::wifi::*;
use esp_idf_svc::netif::*;
use esp_idf_svc::sysloop::*;
use esp_idf_svc::httpd as idf;

use esp_idf_hal::prelude::*;
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_hal::ledc::{config::TimerConfig, Channel, Timer};

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
fn start_http_srv(mutex: Arc<(Mutex<Option<u32>>, Condvar)>) -> Result<idf::Server> {
    let route_root_closure = |_| {
        let html = index_html();
        Ok(html.into())
    };

    let route_led_closure = |req: Request| {
        let now = get_cur_time();
        let mut html = templated(format!("{} ~ Invalid cmd!", now));
        match req.query_string() {
            Some(query_str) => {
                if query_str == "off" {
                    unsafe {
                        G_LED_ON = false;
                    }
                    html = templated(format!("{} ~ The LED is off.", now));
                } else if query_str == "on" {
                    unsafe {
                        G_LED_ON = true;
                    }
                    html = templated(format!("{} ~ The LED is fading in/out ...", now));
                }
            }
            None => {}
        }
        Ok(html.into())
    };

    let server = idf::ServerRegistry::new()
        .at("/")
        .get(route_root_closure)?
        .at("/led")
        .get(route_led_closure)?
        .at("/foo")
        .get(|_| bail!("Boo, something happened!"))?
        .at("/bar")
        .get(|_| {
            Response::new(403)
                .status_message("No permissions")
                .body("You have no permissions to access this page".into())
                .into()
        })?;

    server.start(&Default::default())
}

/*
#[allow(unused_variables)]
#[cfg(feature = "experimental")]
fn start_http_srv(
    mutex: Arc<(Mutex<Option<u32>>, Condvar)>,
) -> Result<esp_idf_svc::http::server::EspHttpServer> {
    use embedded_svc::http::server::registry::Registry;
    use embedded_svc::http::server::Response;

    let mut server = esp_idf_svc::http::server::EspHttpServer::new(&Default::default())?;

    server.handle_get("/", |_req, resp| {
        let html = index_html();
        resp.send_str(&html)?;
        Ok(())
    })?;

    Ok(server)
}
*/

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

    wifi_obj.set_configuration(&Configuration::Mixed(
        ClientConfiguration {
            ssid: SSID.into(),
            password: PASS.into(),
            channel,
            ..Default::default()
        },
        AccessPointConfiguration {
            ssid: "aptest".into(),
            channel: channel.unwrap_or(1),
            ..Default::default()
        },
    ))?;

    info!("WiFi configuration set, about to get status");

    wifi_obj
        .wait_status_with_timeout(Duration::from_secs(20), |status| !status.is_transitional())
        .map_err(|e| anyhow::anyhow!("Unexpected WiFi status: {:?}", e))?;

    let status = wifi_obj.get_status();

    if let Status(
        ClientStatus::Started(ClientConnectionStatus::Connected(ClientIpStatus::Done(
            _ip_settings,
        ))),
        ApStatus::Started(ApIpStatus::Done),
    ) = status
    {
        info!("WiFi connected");
    } else {
        bail!("Unexpected WiFi status: {:?}", status);
    }

    Ok(wifi_obj)
}

fn templated(content: impl AsRef<str>) -> String {
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

fn index_html() -> String {
    let now = get_cur_time();
    println!("{} ~ Got a request path: /", now);
    templated(format!("{} ~ Hello from mcu!", now))
}
