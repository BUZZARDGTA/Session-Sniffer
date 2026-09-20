"""Parameters control panel for the Player Identifier."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QSpinBox,
    QWidget,
)

from session_sniffer.guis._player_identifier_core import (
    BASELINE_CONTAMINATION_MIN_SAMPLES,
    BASELINE_CONTAMINATION_SECONDS,
    BASELINE_CONTAMINATION_ZSCORE,
    BASELINE_MAX_SECONDS,
    BASELINE_MIN_SAMPLES,
    SESSION_DRIFT_ZSCORE_THRESHOLD,
    SPIKE_MIN_ZSCORE,
    SPIKE_SUSTAINED_SECONDS,
)


class PlayerIdentifierParamsWidget(QGroupBox):
    """Control panel displaying detection parameters for Player Identifier."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the parameters control panel."""
        super().__init__('Parameters', parent)

        params_layout = QHBoxLayout(self)

        left_form = QFormLayout()
        left_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        center_form = QFormLayout()
        center_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        right_form = QFormLayout()
        right_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        params_layout.addLayout(left_form)
        params_layout.addLayout(center_form)
        params_layout.addLayout(right_form)

        self._spike_zscore_input = QDoubleSpinBox()
        self._spike_zscore_input.setRange(1.0, 20.0)
        self._spike_zscore_input.setSingleStep(0.5)
        self._spike_zscore_input.setDecimals(1)
        self._spike_zscore_input.setValue(SPIKE_MIN_ZSCORE)
        self._spike_zscore_input.setToolTip(
            'Minimum z-score for an IP to be considered spiking during the Resolve phase.\n\n'
            'Higher = only very dramatic traffic increases trigger detection.\n'
            'Lower = more sensitive but may produce false positives.',
        )
        left_form.addRow('Spike Z-Score:', self._spike_zscore_input)

        self._spike_seconds_input = QSpinBox()
        self._spike_seconds_input.setRange(1, 30)
        self._spike_seconds_input.setValue(SPIKE_SUSTAINED_SECONDS)
        self._spike_seconds_input.setSuffix('s')
        self._spike_seconds_input.setToolTip(
            'Consecutive seconds an IP must stay above the spike z-score to be confirmed as the target.\n\n'
            'Higher = fewer false positives but takes longer to confirm.\n'
            'Lower = faster confirmation but may match brief coincidental traffic bursts.',
        )
        center_form.addRow('Spike Duration:', self._spike_seconds_input)

        self._contam_zscore_input = QDoubleSpinBox()
        self._contam_zscore_input.setRange(3.0, 50.0)
        self._contam_zscore_input.setSingleStep(0.5)
        self._contam_zscore_input.setDecimals(1)
        self._contam_zscore_input.setValue(BASELINE_CONTAMINATION_ZSCORE)
        self._contam_zscore_input.setToolTip(
            'Z-score threshold for detecting baseline contamination (active during baseline and ready phases).\n\n'
            'If an IP sustains this z-score for the contamination duration, the baseline is aborted.\n'
            'Higher = less likely to abort on normal traffic variation.\n'
            'Lower = more aggressively detects movement or spectating.',
        )
        right_form.addRow('Contamination Z-Score:', self._contam_zscore_input)

        self._contamination_seconds_input = QSpinBox()
        self._contamination_seconds_input.setRange(1, 30)
        self._contamination_seconds_input.setValue(BASELINE_CONTAMINATION_SECONDS)
        self._contamination_seconds_input.setSuffix('s')
        self._contamination_seconds_input.setToolTip(
            'Consecutive seconds an IP must stay above the contamination z-score to trigger a baseline abort.\n\n'
            'Higher = more tolerant of brief traffic bursts (fewer false aborts).\n'
            'Lower = aborts sooner if any IP stays elevated.',
        )
        left_form.addRow('Contamination Duration:', self._contamination_seconds_input)

        self._contam_min_samples_input = QSpinBox()
        self._contam_min_samples_input.setRange(5, 60)
        self._contam_min_samples_input.setValue(BASELINE_CONTAMINATION_MIN_SAMPLES)
        self._contam_min_samples_input.setSuffix('s')
        self._contam_min_samples_input.setToolTip(
            'Minimum samples collected before contamination checking activates.\n\n'
            'Prevents false aborts right at the start when the baseline has very little data.\n'
            'Lower = contamination detection activates sooner.',
        )
        center_form.addRow('Contamination Grace Period:', self._contam_min_samples_input)

        self._min_samples_input = QSpinBox()
        self._min_samples_input.setRange(5, 120)
        self._min_samples_input.setValue(BASELINE_MIN_SAMPLES)
        self._min_samples_input.setSuffix('s')
        self._min_samples_input.setToolTip(
            'Minimum number of 1-second samples required before the baseline can auto-lock on convergence.\n\n'
            'More samples = more statistically accurate baseline.\n'
            'Fewer = faster lock but potentially less reliable detection.',
        )
        right_form.addRow('Min Baseline Samples:', self._min_samples_input)

        self._max_seconds_input = QSpinBox()
        self._max_seconds_input.setRange(10, 300)
        self._max_seconds_input.setValue(BASELINE_MAX_SECONDS)
        self._max_seconds_input.setSuffix('s')
        self._max_seconds_input.setToolTip(
            'Hard time limit for the baseline phase.\n\n'
            'If traffic has not converged within this many seconds, the baseline locks anyway.\n'
            'Increase for very variable or noisy network conditions.',
        )
        left_form.addRow('Baseline Timeout:', self._max_seconds_input)

        self._drift_threshold_input = QDoubleSpinBox()
        self._drift_threshold_input.setRange(1.0, 30.0)
        self._drift_threshold_input.setSingleStep(0.5)
        self._drift_threshold_input.setDecimals(1)
        self._drift_threshold_input.setValue(SESSION_DRIFT_ZSCORE_THRESHOLD)
        self._drift_threshold_input.setToolTip(
            'Aggregate z-score threshold for detecting session-wide traffic drift.\n\n'
            'If the median z-score across all tracked IPs exceeds this magnitude, '
            'the tool assumes the session has changed and aborts.\n'
            'Higher = more tolerant of session-wide traffic shifts.',
        )
        center_form.addRow('Session Drift Z-Score:', self._drift_threshold_input)

    @property
    def spike_min_zscore(self) -> float:
        """Minimum z-score required to consider an IP spiking."""
        return self._spike_zscore_input.value()

    @property
    def spike_sustained_seconds(self) -> int:
        """Sustained seconds required above the spike threshold to confirm a player match."""
        return self._spike_seconds_input.value()

    @property
    def contamination_zscore(self) -> float:
        """Z-score threshold for detecting baseline contamination."""
        return self._contam_zscore_input.value()

    @property
    def contamination_seconds(self) -> int:
        """Sustained seconds above contamination z-score that triggers an abort."""
        return self._contamination_seconds_input.value()

    @property
    def contamination_min_samples(self) -> int:
        """Minimum baseline samples collected before contamination checking begins."""
        return self._contam_min_samples_input.value()

    @property
    def baseline_min_samples(self) -> int:
        """Minimum samples needed before baseline can lock upon convergence."""
        return self._min_samples_input.value()

    @property
    def baseline_max_seconds(self) -> int:
        """Maximum duration in seconds before the baseline phase auto-locks."""
        return self._max_seconds_input.value()

    @property
    def session_drift_threshold(self) -> float:
        """Median z-score drift threshold across all IPs to detect session changes."""
        return self._drift_threshold_input.value()
