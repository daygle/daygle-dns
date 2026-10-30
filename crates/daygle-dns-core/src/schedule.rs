//! Filtering schedules: weekly time windows during which a filtering group
//! applies.
//!
//! Times are wall-clock times in the server's display time zone
//! (`display.time_zone`), which the server sets here at startup and whenever
//! the setting changes.

use std::sync::RwLock;

use chrono::{Datelike, TimeZone, Timelike, Utc};
use serde::{Deserialize, Serialize};

/// Day names, Monday first (the order of [`chrono::Weekday::num_days_from_monday`]).
pub const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

/// Full day names accepted alongside the short ones.
const DAY_NAMES: [(&str, &str); 7] = [
    ("mon", "monday"),
    ("tue", "tuesday"),
    ("wed", "wednesday"),
    ("thu", "thursday"),
    ("fri", "friday"),
    ("sat", "saturday"),
    ("sun", "sunday"),
];

/// One weekly window: on each of `days`, from `start` until `end` (both
/// `HH:MM`). An `end` earlier than `start` runs past midnight into the next
/// day; equal times cover the whole day. No days means every day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleWindow {
    #[serde(default)]
    pub days: Vec<String>,
    pub start: String,
    pub end: String,
}

/// A moment in the week: day (0 = Monday) and minute of the day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeekTime {
    pub day: u32,
    pub minute: u32,
}

/// A window parsed for evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledWindow {
    /// Bit `n` set: the window starts on day `n` (0 = Monday).
    days: u8,
    start: u32,
    end: u32,
}

impl CompiledWindow {
    /// Parse a window; `Err` names what is wrong with it.
    pub fn parse(window: &ScheduleWindow) -> Result<Self, String> {
        let mut days = 0u8;
        for day in &window.days {
            let lowered = day.trim().to_ascii_lowercase();
            let index = DAYS
                .iter()
                .position(|d| lowered == *d || DAY_NAMES.contains(&(*d, lowered.as_str())))
                .ok_or_else(|| format!("'{day}' is not a day of the week"))?;
            days |= 1 << index;
        }
        if days == 0 {
            days = 0x7f;
        }
        Ok(Self {
            days,
            start: parse_time(&window.start)?,
            end: parse_time(&window.end)?,
        })
    }

    /// Whether `now` falls inside this window.
    pub fn contains(&self, now: WeekTime) -> bool {
        let starts_on = |day: u32| self.days & (1 << (day % 7)) != 0;
        if self.start == self.end {
            return starts_on(now.day);
        }
        if self.start < self.end {
            return starts_on(now.day) && (self.start..self.end).contains(&now.minute);
        }
        // Past midnight: the evening of a listed day, or the morning after.
        (starts_on(now.day) && now.minute >= self.start)
            || (starts_on(now.day + 6) && now.minute < self.end)
    }
}

/// Parse `HH:MM` (24-hour) into a minute of the day.
fn parse_time(text: &str) -> Result<u32, String> {
    let bad = || format!("'{text}' is not a time (use HH:MM, 24-hour)");
    let (h, m) = text.trim().split_once(':').ok_or_else(bad)?;
    let (hl, ml) = (h.len(), m.len());
    let h: u32 = h.parse().map_err(|_| bad())?;
    let m: u32 = m.parse().map_err(|_| bad())?;
    if !(1..=2).contains(&hl) || ml != 2 || h > 23 || m > 59 {
        return Err(bad());
    }
    Ok(h * 60 + m)
}

/// Check a schedule, naming the first problem.
pub fn validate(windows: &[ScheduleWindow]) -> Result<(), String> {
    windows
        .iter()
        .try_for_each(|w| CompiledWindow::parse(w).map(|_| ()))
}

/// Whether a schedule is active at `now`: always when it has no windows,
/// else when any window contains `now`.
pub fn active(windows: &[CompiledWindow], now: WeekTime) -> bool {
    windows.is_empty() || windows.iter().any(|w| w.contains(now))
}

/// The time zone schedules are read in: `None` for the server's own.
static TIME_ZONE: RwLock<Option<chrono_tz::Tz>> = RwLock::new(None);

/// Set the time zone schedules are read in, from a `display.time_zone`
/// value: `system` (or a name not in the time zone database) uses the
/// server's own zone.
pub fn set_time_zone(name: &str) {
    let tz = if name.eq_ignore_ascii_case("utc") {
        Some(chrono_tz::UTC)
    } else {
        name.parse::<chrono_tz::Tz>().ok()
    };
    if let Ok(mut slot) = TIME_ZONE.write() {
        *slot = tz;
    }
}

/// The current moment in the week, in the schedule time zone.
pub fn now() -> WeekTime {
    now_and_today().0
}

/// The current calendar date in the same time zone used by [`now`].
pub fn today() -> chrono::NaiveDate {
    now_and_today().1
}

/// One consistent snapshot of local schedule time and date.
pub fn now_and_today() -> (WeekTime, chrono::NaiveDate) {
    let utc = Utc::now();
    let tz = TIME_ZONE.read().ok().and_then(|slot| *slot);
    match tz {
        Some(tz) => {
            let local = tz.from_utc_datetime(&utc.naive_utc());
            (week_time(&local), local.date_naive())
        }
        None => {
            let local = utc.with_timezone(&chrono::Local);
            (week_time(&local), local.date_naive())
        }
    }
}

fn week_time<T: Datelike + Timelike>(t: &T) -> WeekTime {
    WeekTime {
        day: t.weekday().num_days_from_monday(),
        minute: t.hour() * 60 + t.minute(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(days: &[&str], start: &str, end: &str) -> CompiledWindow {
        CompiledWindow::parse(&ScheduleWindow {
            days: days.iter().map(|d| d.to_string()).collect(),
            start: start.to_string(),
            end: end.to_string(),
        })
        .unwrap()
    }

    fn at(day: u32, time: &str) -> WeekTime {
        WeekTime {
            day,
            minute: parse_time(time).unwrap(),
        }
    }

    #[test]
    fn same_day_window() {
        let school = window(&["mon", "tue", "wed", "thu", "fri"], "08:30", "15:00");
        assert!(school.contains(at(0, "08:30")));
        assert!(school.contains(at(4, "14:59")));
        assert!(!school.contains(at(4, "15:00")));
        assert!(!school.contains(at(0, "08:29")));
        assert!(!school.contains(at(5, "10:00")));
    }

    #[test]
    fn window_past_midnight_belongs_to_the_day_it_starts() {
        let bedtime = window(&["fri"], "21:00", "07:00");
        assert!(bedtime.contains(at(4, "23:00")));
        assert!(bedtime.contains(at(5, "06:59")));
        assert!(!bedtime.contains(at(5, "07:00")));
        assert!(!bedtime.contains(at(4, "06:00")));
        // Sunday night runs into Monday morning.
        let sunday = window(&["sun"], "22:00", "06:00");
        assert!(sunday.contains(at(0, "05:00")));
        assert!(!sunday.contains(at(1, "05:00")));
    }

    #[test]
    fn all_days_and_whole_days() {
        let every_day = window(&[], "12:00", "13:00");
        assert!((0..7).all(|d| every_day.contains(at(d, "12:30"))));
        let saturday = window(&["Saturday"], "00:00", "00:00");
        assert!(saturday.contains(at(5, "00:00")));
        assert!(saturday.contains(at(5, "23:59")));
        assert!(!saturday.contains(at(6, "00:00")));
        assert!(active(&[], at(3, "03:00")));
    }

    #[test]
    fn bad_windows_are_rejected() {
        let w = |days: &[&str], start: &str, end: &str| ScheduleWindow {
            days: days.iter().map(|d| d.to_string()).collect(),
            start: start.to_string(),
            end: end.to_string(),
        };
        assert!(validate(&[w(&["mon"], "08:00", "17:00")]).is_ok());
        assert!(validate(&[w(&["someday"], "08:00", "17:00")]).is_err());
        assert!(validate(&[w(&[], "24:00", "17:00")]).is_err());
        assert!(validate(&[w(&[], "8", "17:00")]).is_err());
        assert!(validate(&[w(&[], "08:000", "17:00")]).is_err());
    }
}
