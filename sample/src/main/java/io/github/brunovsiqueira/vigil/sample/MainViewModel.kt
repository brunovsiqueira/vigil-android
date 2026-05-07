package io.github.brunovsiqueira.vigil.sample

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.brunovsiqueira.vigil.DetectionCategory
import io.github.brunovsiqueira.vigil.Vigil
import io.github.brunovsiqueira.vigil.VigilResult
import io.github.brunovsiqueira.vigil.util.DetectionLogger
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

        viewModelScope.launch {
            val result = Vigil.evaluate(getApplication()) {
                this.includeSensorAnalysis = includeSensorAnalysis
                signingCertSha256 = DEBUG_SIGNING_CERT_SHA256
            }
            _uiState.value = ScanState.Complete(result)
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
    data class Complete(val result: VigilResult) : ScanState()
}
