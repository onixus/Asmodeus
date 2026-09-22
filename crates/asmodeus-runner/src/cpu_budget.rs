//! Cooperative per-worker CPU pacing; not a host-wide cgroup limit.
use std::{
    io,
    time::{Duration, Instant},
};

pub struct CpuBudget {
    start: Instant,
    cpu_start: Duration,
    percent: u32,
}
impl CpuBudget {
    pub fn new(percent: u32) -> io::Result<Self> {
        Ok(Self {
            start: Instant::now(),
            cpu_start: thread_cpu()?,
            percent,
        })
    }
    pub fn delay(&self) -> io::Result<Duration> {
        let used = thread_cpu()?.saturating_sub(self.cpu_start);
        Ok(required_delay(used, self.start.elapsed(), self.percent))
    }
}
fn required_delay(cpu: Duration, wall: Duration, percent: u32) -> Duration {
    cpu.mul_f64(100.0 / f64::from(percent.max(1)))
        .saturating_sub(wall)
}
#[cfg(unix)]
fn thread_cpu() -> io::Result<Duration> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes to a valid initialized timespec, retained
    // for the call; the thread CPU clock requires no owned OS resource.
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Duration::new(value.tv_sec as u64, value.tv_nsec as u32))
}
#[cfg(not(unix))]
fn thread_cpu() -> io::Result<Duration> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "thread CPU pacing requires Unix",
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pacing_applies_signed_budget() {
        assert_eq!(
            required_delay(Duration::from_millis(10), Duration::from_millis(20), 25),
            Duration::from_millis(20)
        );
        assert_eq!(
            required_delay(Duration::from_millis(10), Duration::from_millis(100), 25),
            Duration::ZERO
        );
        assert!(CpuBudget::new(25).unwrap().delay().is_ok());
    }
}
