// ABOUTME: Printing the output devices for `audio-devices list`, over the enumeration the
// ABOUTME: library does.

//! The device listing.
//!
//! Only the printing lives here. Finding and checking devices is
//! [`sendspin::audio::devices`], because an application embedding this crate has to do the same
//! thing and should not have to reimplement it from the flags.

use sendspin::audio::devices::output_devices;

/// Print the devices, the way `sendspin audio-devices list` reports them.
pub fn list_devices() -> Result<(), String> {
    let devices = output_devices()?;
    if devices.is_empty() {
        println!("No audio output devices found.");
        return Ok(());
    }
    println!("Audio output devices:\n");
    for device in &devices {
        match &device.description {
            Some(description) => {
                println!("  [{}] {}\n      {description}", device.index, device.id)
            }
            None => println!("  [{}] {}", device.index, device.id),
        }
    }
    println!("\nSelect one with --audio-device <index>, or by name:");
    println!("  sendspin daemon --audio-device {}", devices[0].index);
    println!("  sendspin daemon --audio-device {:?}", devices[0].id);
    Ok(())
}
