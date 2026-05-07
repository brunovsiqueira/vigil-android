package io.github.brunovsiqueira.vigil.sample

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.brunovsiqueira.vigil.VigilEngine
import io.github.brunovsiqueira.vigil.TamperVerdict
import io.github.brunovsiqueira.vigil.util.DetectionLogger
import io.github.brunovsiqueira.vigil.detectors.CloningDetector
import io.github.brunovsiqueira.vigil.detectors.EmulatorDetector
import io.github.brunovsiqueira.vigil.detectors.HookingDetector
import io.github.brunovsiqueira.vigil.detectors.IntegrityDetector
import io.github.brunovsiqueira.vigil.detectors.RootDetector
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class MainViewModel(application: Application) : AndroidViewModel(application) {

    init {
        DetectionLogger.enabled = BuildConfig.DEBUG
    }

    private val _uiState = MutableStateFlow<ScanState>(ScanState.Idle)
    val uiState: StateFlow<ScanState> = _uiState.asStateFlow()

    fun runFastScan() = runScan(includeSensorAnalysis = false)

    fun runThoroughScan() = runScan(includeSensorAnalysis = true)

    private fun runScan(includeSensorAnalysis: Boolean) {
        if (_uiState.value is ScanState.Scanning) return
        _uiState.value = ScanState.Scanning

        val engine = VigilEngine.Builder()
            .addDetector(EmulatorDetector(includeSensorAnalysis = includeSensorAnalysis))
            .addDetector(CloningDetector())
            .addDetector(IntegrityDetector(
                // SHA-256 of debug signing cert (apksigner verify --print-certs app-debug.apk)
                // Production: use Play App Signing key from Play Console
                expectedSigningCertSha256 = DEBUG_SIGNING_CERT_SHA256,
            ))
            .addDetector(HookingDetector())
            .addDetector(RootDetector())
            .build()

        viewModelScope.launch {
            val verdict = engine.evaluate(getApplication())
            _uiState.value = ScanState.Complete(verdict)
        }
    }

    companion object {
        private const val DEBUG_SIGNING_CERT_SHA256 =
            "f9c0679ec146e15dcaab36279624b851b4b74dac0a393a95735912b6cc719291"
    }
}

sealed class ScanState {
    data object Idle : ScanState()
    data object Scanning : ScanState()
    data class Complete(val verdict: TamperVerdict) : ScanState()
}
