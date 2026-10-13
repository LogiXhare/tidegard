//! Reading settings from the environment, under the product's name and
//! its first one.
//!
//! The product was WetechiNetMon until 1.0.0-rc.1 and is Tidegard since
//! (ADR 0058). Every setting is `TIDEGARD_...`; one still set under its
//! old name, `WETECHINETMON_...`, keeps working through the 1.x series,
//! with a warning, so an upgrade does not stop on a settings file
//! nobody has renamed yet. The new name wins when both are set.

use std::env::VarError;

/// The prefix of every setting.
pub const PREFIX: &str = "TIDEGARD_";

/// The prefix settings had before the rename, still read in 1.x.
pub const LEGACY_PREFIX: &str = "WETECHINETMON_";

/// The old name of a setting, if it has one.
pub fn legacy_name(name: &str) -> Option<String> {
    name.strip_prefix(PREFIX)
        .map(|rest| format!("{LEGACY_PREFIX}{rest}"))
}

/// Reads `name`, or failing that its old name, with a warning on standard
/// error that names both. `Ok(None)` when neither is set.
pub fn var(name: &str) -> Result<Option<String>, VarError> {
    var_from(name, |key| std::env::var(key))
}

/// [`var`] over any lookup, so tests need not touch the process
/// environment.
pub fn var_from(
    name: &str,
    lookup: impl Fn(&str) -> Result<String, VarError>,
) -> Result<Option<String>, VarError> {
    match lookup(name) {
        Ok(value) => return Ok(Some(value)),
        Err(VarError::NotPresent) => {}
        Err(error) => return Err(error),
    }
    let Some(legacy) = legacy_name(name) else {
        return Ok(None);
    };
    match lookup(&legacy) {
        Ok(value) => {
            eprintln!("warning: {legacy} is deprecated; rename it to {name}");
            Ok(Some(value))
        }
        Err(VarError::NotPresent) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Result<String, VarError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key| map.get(key).cloned().ok_or(VarError::NotPresent)
    }

    #[test]
    fn the_new_name_is_read_first_and_the_old_one_still_works() {
        let both = lookup(&[("TIDEGARD_X", "new"), ("WETECHINETMON_X", "old")]);
        assert_eq!(var_from("TIDEGARD_X", &both), Ok(Some("new".into())));
        let old = lookup(&[("WETECHINETMON_X", "old")]);
        assert_eq!(var_from("TIDEGARD_X", &old), Ok(Some("old".into())));
        assert_eq!(var_from("TIDEGARD_X", lookup(&[])), Ok(None));
    }

    #[test]
    fn only_product_settings_have_an_old_name() {
        assert_eq!(
            legacy_name("TIDEGARD_API_BIND").as_deref(),
            Some("WETECHINETMON_API_BIND")
        );
        assert_eq!(legacy_name("HOSTNAME"), None);
        assert_eq!(var_from("HOSTNAME", lookup(&[])), Ok(None));
    }
}
