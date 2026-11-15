"""GTA V session, High Rate Monitor, Spike Alerts, and Player Identifier setting metadata."""

from session_sniffer.constants.standalone import (
    SPIKE_SOUND_MODES,
    SPIKE_SOUND_PRESETS,
    SPIKE_SOUND_SCOPES,
    SPIKE_TRIGGER_METRICS,
)
from session_sniffer.settings.meta import SettingMeta, SettingType

GTAV_SESSION_SETTING_METADATA: dict[str, SettingMeta] = {
    'gui_session_host_detection': SettingMeta(
        category='GTA V', group='Session Host', display_label='Session Host Detection', setting_type=SettingType.BOOLEAN,
        tooltip='Detect and track the session host for supported game sessions.',
    ),
    'gui_session_host_icon': SettingMeta(
        category='GTA V', group='Session Host', display_label='Session Host Table Icon', setting_type=SettingType.BOOLEAN,
        tooltip='Display the crown icon next to the session host IP address in the session tables.',
    ),
    'gta5_relay_icon': SettingMeta(
        category='GTA V', group='Session Relays', display_label='Session Relay Table Icon', setting_type=SettingType.BOOLEAN,
        tooltip='Display the relay icon next to detected GTA5 relay IP addresses in the session tables.',
    ),
    'gta5_relay_packet_threshold': SettingMeta(
        category='GTA V', group='Session Relays', display_label='Session Relay Packet Threshold', setting_type=SettingType.INTEGER,
        tooltip='Minimum number of packets that must be exchanged with a relay IP before it is detected as an active relay.',
        min_value=10, max_value=10000, step=1, suffix=' packets',
    ),
    'gta5_relay_min_pps': SettingMeta(
        category='GTA V', group='Session Relays', display_label='Session Relay Minimum PPS', setting_type=SettingType.INTEGER,
        tooltip='Minimum Packets Per Second required during the consecutive traffic streak to confirm an active relay.',
        min_value=1, max_value=100, step=1, suffix=' PPS',
    ),
    'gta5_relay_streak_duration': SettingMeta(
        category='GTA V', group='Session Relays', display_label='Session Relay Streak Duration', setting_type=SettingType.INTEGER,
        tooltip='Number of consecutive seconds a relay IP must sustain the minimum PPS rate before triggering relay detection.',
        min_value=1, max_value=30, step=1, suffix=' seconds',
    ),
    'gta5_relay_min_bandwidth_kb': SettingMeta(
        category='GTA V', group='Session Relays', display_label='Session Relay Minimum Bandwidth', setting_type=SettingType.INTEGER,
        tooltip='Minimum bandwidth in kilobytes (KB) on the primary relay direction (Download or Upload) required for relay detection.',
        min_value=1, max_value=1024, step=1, suffix=' KB',
    ),
    'high_rate_monitor_mode': SettingMeta(
        category='GTA V', group='Player High Rate Monitor', display_label='Player High Rate Monitor Mode', setting_type=SettingType.ENUM,
        tooltip=(
            'Detection mode for flagging high packet-rate players.\n\n'
            'Smart: Dynamically calculates the average PPS and BPS of connected players and flags players '
            'exceeding the session averages with a margin and minimum floor.\n'
            'Manual: Flags players exceeding fixed PPS and BPS thresholds.'
        ),
        allowed_values=('Smart', 'Manual'),
    ),
    'high_rate_monitor_icon': SettingMeta(
        category='GTA V', group='Player High Rate Monitor', display_label='Player High Rate Monitor Table Icon', setting_type=SettingType.BOOLEAN,
        tooltip='Display the Player High Rate Monitor speedometer icon in the IP Address column for players exceeding rate thresholds.',
    ),
    'high_rate_monitor_run_in_background': SettingMeta(
        category='GTA V', group='Player High Rate Monitor', display_label='Player High Rate Monitor Run in Background', setting_type=SettingType.BOOLEAN,
        tooltip=(
            'When enabled, the Player High Rate Monitor continuously tracks player packet rates in the background even when the Player Resolver window is closed.\n'
            'When disabled, player rate monitoring is only active while the Player Resolver window is open.'
        ),
    ),
    'high_rate_monitor_auto_select': SettingMeta(
        category='GTA V', group='Player High Rate Monitor', display_label='Player High Rate Monitor Auto-Select in Table', setting_type=SettingType.BOOLEAN,
        tooltip='Automatically select flagged high-rate players in the connected-players table.',
    ),
    'high_rate_monitor_pps_threshold': SettingMeta(
        category='GTA V', group='Player High Rate Monitor', display_label='Player High Rate Monitor PPS Threshold', setting_type=SettingType.INTEGER,
        tooltip='Minimum Packets Per Second required to flag a player as high-rate traffic.', min_value=20, max_value=50, step=1, suffix=' PPS',
    ),
    'high_rate_monitor_bps_threshold': SettingMeta(
        category='GTA V', group='Player High Rate Monitor', display_label='Player High Rate Monitor BPS Threshold', setting_type=SettingType.INTEGER,
        tooltip='Minimum bandwidth in kilobytes per second (KB/s) required to flag a player as high-rate traffic.', min_value=3, max_value=500, step=1, suffix=' KB/s',
    ),
    'high_rate_monitor_duration_threshold': SettingMeta(
        category='GTA V', group='Player High Rate Monitor', display_label='Player High Rate Monitor Duration', setting_type=SettingType.INTEGER,
        tooltip='Number of consecutive seconds player traffic must exceed both PPS and BPS thresholds.', min_value=1, max_value=10, step=1, suffix=' seconds',
    ),
    'high_rate_monitor_spike_sound_scope': SettingMeta(
        category='GTA V', group='Player High Rate Monitor', subgroup='Spike Alerts', display_label='Spike Sound Scope', setting_type=SettingType.ENUM,
        tooltip=(
            'Controls where spike alert sounds are active.\n\n'
            'Disabled: Mute all traffic spike sounds.\n'
            'Open Graphs: Play spike sounds only for players with an open Rate Graph window.\n'
            'Global: Play spike sounds for any monitored connected player in the session, even without an open Rate Graph window.'
        ),
        allowed_values=SPIKE_SOUND_SCOPES,
    ),
    'high_rate_monitor_spike_sound_mode': SettingMeta(
        category='GTA V', group='Player High Rate Monitor', subgroup='Spike Alerts', display_label='Spike Sound Behavior', setting_type=SettingType.ENUM,
        tooltip=(
            'Playback behavior when a player triggers a traffic spike.\n\n'
            'Once on Spike: Play once when traffic crosses above the threshold.\n'
            'Repeating: Repeat at the configured interval for as long as the spike persists.\n'
            'Start & End: Play on spike start and play a descending chime when traffic drops back below the threshold.\n'
            'Repeating + End: Repeat while spiking and play a descending chime when the spike ends.\n'
            'Adaptive Geiger: Dynamically accelerate the repeat cadence as traffic climbs further above the threshold, switching to an urgent tone on heavy spikes.'
        ),
        allowed_values=SPIKE_SOUND_MODES,
    ),
    'high_rate_monitor_spike_repeat_interval': SettingMeta(
        category='GTA V', group='Player High Rate Monitor', subgroup='Spike Alerts', display_label='Spike Sound Repeat Interval', setting_type=SettingType.INTEGER,
        tooltip='Base interval in seconds between repeated spike sounds while a spike remains active (used as the baseline cadence in Adaptive Geiger mode).',
        min_value=1, max_value=30, step=1, suffix=' seconds',
    ),
    'high_rate_monitor_spike_sound_preset': SettingMeta(
        category='GTA V', group='Player High Rate Monitor', subgroup='Spike Alerts', display_label='Spike Sound Preset', setting_type=SettingType.ENUM,
        tooltip='Built-in audio tone played when a traffic spike is triggered. Click Preview to test the selected tone.',
        allowed_values=SPIKE_SOUND_PRESETS,
    ),
    'high_rate_monitor_spike_trigger_metric': SettingMeta(
        category='GTA V', group='Player High Rate Monitor', subgroup='Spike Alerts', display_label='Spike Trigger Condition', setting_type=SettingType.ENUM,
        tooltip=(
            'Condition that activates spike sound and visual graph highlights.\n\n'
            'Either (PPS or BPS): Trigger immediately as soon as either PPS or KB/s reaches its threshold.\n'
            'Follow Monitor: Trigger only after sustaining the active High Rate Monitor mode and Duration requirement.\n'
            'Both (PPS and BPS): Trigger immediately when both PPS and KB/s reach their thresholds simultaneously.\n'
            'PPS Only: Trigger immediately when PPS reaches its threshold.\n'
            'BPS Only: Trigger immediately when KB/s reaches its threshold.'
        ),
        allowed_values=SPIKE_TRIGGER_METRICS,
    ),
    'high_rate_monitor_spike_visual_alert': SettingMeta(
        category='GTA V', group='Player High Rate Monitor', subgroup='Spike Alerts', display_label='Spike Visual Highlight', setting_type=SettingType.BOOLEAN,
        tooltip=(
            'Highlight spiking Player Rate Graph panels with an alert border, danger-zone tint above the threshold, '
            'and a live SPIKE badge showing streak duration and peak rate.'
        ),
    ),
    'high_rate_monitor_auto_open_graph': SettingMeta(
        category='GTA V', group='Player High Rate Monitor', subgroup='Spike Alerts', display_label='Auto-Open Graph on Spike', setting_type=SettingType.BOOLEAN,
        tooltip='Automatically open a live Player Rate Graph window (without stealing active window focus) whenever a player becomes flagged by the High Rate Monitor.',
    ),
    'player_identifier_icon': SettingMeta(
        category='GTA V', group='Player Identifier', display_label='Player Identifier Table Icon', setting_type=SettingType.BOOLEAN,
        tooltip='Display the Player Identifier target icon in the IP Address column for players identified by the tool.',
    ),
    'player_identifier_spike_zscore': SettingMeta(
        category='GTA V', group='Player Identifier', display_label='Player Identifier Spike Z-Score', setting_type=SettingType.FLOAT,
        tooltip='Statistical sensitivity threshold (z-score) to detect traffic spikes during correlation.', min_value=1.0, max_value=20.0, step=0.5,
    ),
    'player_identifier_spike_seconds': SettingMeta(
        category='GTA V', group='Player Identifier', display_label='Player Identifier Spike Duration', setting_type=SettingType.INTEGER,
        tooltip='Number of consecutive seconds a traffic burst must sustain to identify a player.', min_value=1, max_value=30, step=1, suffix=' seconds',
    ),
    'player_identifier_baseline_seconds': SettingMeta(
        category='GTA V', group='Player Identifier', display_label='Player Identifier Baseline Duration', setting_type=SettingType.INTEGER,
        tooltip='Duration in seconds to profile quiet background traffic before triggering player resolution.', min_value=5, max_value=120, step=1, suffix=' seconds',
    ),
    'player_identifier_contamination_zscore': SettingMeta(
        category='GTA V', group='Player Identifier', display_label='Player Identifier Contamination Z-Score', setting_type=SettingType.FLOAT,
        tooltip='Z-score threshold for detecting baseline contamination. Aborts baseline if an IP sustains this z-score.', min_value=3.0, max_value=50.0, step=0.5,
    ),
    'player_identifier_contamination_seconds': SettingMeta(
        category='GTA V', group='Player Identifier', display_label='Player Identifier Contamination Duration', setting_type=SettingType.INTEGER,
        tooltip='Consecutive seconds an IP must stay above the contamination z-score to trigger a baseline abort.', min_value=1, max_value=30, step=1, suffix=' seconds',
    ),
    'player_identifier_contamination_min_samples': SettingMeta(
        category='GTA V', group='Player Identifier', display_label='Player Identifier Contamination Grace Period', setting_type=SettingType.INTEGER,
        tooltip='Minimum samples collected before contamination checking activates.', min_value=5, max_value=60, step=1, suffix=' samples',
    ),
    'player_identifier_baseline_timeout': SettingMeta(
        category='GTA V', group='Player Identifier', display_label='Player Identifier Baseline Timeout', setting_type=SettingType.INTEGER,
        tooltip='Maximum time limit in seconds for the baseline phase before forcing baseline lock.', min_value=10, max_value=300, step=1, suffix=' seconds',
    ),
    'player_identifier_session_drift_zscore': SettingMeta(
        category='GTA V', group='Player Identifier', display_label='Player Identifier Session Drift Z-Score', setting_type=SettingType.FLOAT,
        tooltip='Aggregate z-score threshold across all tracked IPs for detecting session-wide traffic drift.', min_value=1.0, max_value=30.0, step=0.5,
    ),
}
