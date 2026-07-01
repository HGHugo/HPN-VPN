use tauri::State;

use crate::config::Settings;
use crate::error::CommandError;
use crate::state::LogLevel;

use super::AppStateRef;

fn normalize_settings(mut settings: Settings) -> Settings {
    settings.kill_switch = true;
    settings
}

pub fn get_settings(state: State<'_, AppStateRef>) -> Settings {
    state.read().settings.clone()
}

pub fn save_settings(
    state: State<'_, AppStateRef>,
    settings: Settings,
) -> Result<(), CommandError> {
    let mut state = state.write();

    let settings = normalize_settings(settings);

    state.settings = settings;
    state.add_log(LogLevel::Info, "Settings saved");

    state.save_settings().map_err(CommandError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_settings_enforces_kill_switch() {
        let input = Settings {
            kill_switch: false,
            ..Settings::default()
        };
        let output = normalize_settings(input);
        assert!(output.kill_switch);
    }
}
