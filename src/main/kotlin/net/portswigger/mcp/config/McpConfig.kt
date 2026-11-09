package net.portswigger.mcp.config

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import java.lang.ref.WeakReference
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

private const val TARGET_SEPARATOR = "\n"
private const val DEFAULT_INTERCEPTION_TIMEOUT_SECONDS = 60
private const val MIN_INTERCEPTION_TIMEOUT_SECONDS = 5
private const val MAX_INTERCEPTION_TIMEOUT_SECONDS = 120

class McpConfig(storage: PersistedObject, private val logging: Logging) {

    var enabled by storage.boolean(true)
    var readOnlyMode by storage.boolean(true)
    var requireBearerToken by storage.boolean(true)
    var bearerToken by storage.string("")
    var configEditingTooling by storage.boolean(false)
    var host by storage.string("127.0.0.1")
    var port by storage.int(9876)
    var requireHttpRequestApproval by storage.boolean(true)
    var requireDataAccessApproval by storage.boolean(true)

    private var storedInterceptionTimeoutSeconds by storage.int(DEFAULT_INTERCEPTION_TIMEOUT_SECONDS)
    var interceptionTimeoutSeconds: Int
        get() = storedInterceptionTimeoutSeconds.coerceIn(
            MIN_INTERCEPTION_TIMEOUT_SECONDS,
            MAX_INTERCEPTION_TIMEOUT_SECONDS
        )
        set(value) {
            require(value in MIN_INTERCEPTION_TIMEOUT_SECONDS..MAX_INTERCEPTION_TIMEOUT_SECONDS) {
                "Interception timeout must be between $MIN_INTERCEPTION_TIMEOUT_SECONDS and $MAX_INTERCEPTION_TIMEOUT_SECONDS seconds"
            }
            storedInterceptionTimeoutSeconds = value
        }

    private var _alwaysAllowHttpHistory by storage.boolean(false)
    var alwaysAllowHttpHistory: Boolean
        get() = _alwaysAllowHttpHistory
        set(value) {
            if (_alwaysAllowHttpHistory != value) {
                _alwaysAllowHttpHistory = value
                notifyDataAccessChanged()
            }
        }

    private var _alwaysAllowWebSocketHistory by storage.boolean(false)
    var alwaysAllowWebSocketHistory: Boolean
        get() = _alwaysAllowWebSocketHistory
        set(value) {
            if (_alwaysAllowWebSocketHistory != value) {
                _alwaysAllowWebSocketHistory = value
                notifyDataAccessChanged()
            }
        }

    private var _alwaysAllowOrganizer by storage.boolean(false)
    var alwaysAllowOrganizer: Boolean
        get() = _alwaysAllowOrganizer
        set(value) {
            if (_alwaysAllowOrganizer != value) {
                _alwaysAllowOrganizer = value
                notifyDataAccessChanged()
            }
        }

    var filterConfigCredentials by storage.boolean(true)

    private var _autoApproveTargets by storage.stringList("")
    private val targetsChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()
    private val dataAccessChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()

    var autoApproveTargets: String
        get() = _autoApproveTargets
        set(value) {
            if (_autoApproveTargets != value) {
                _autoApproveTargets = value
                notifyTargetsChanged()
            }
        }

    init {
        if (storedInterceptionTimeoutSeconds !in MIN_INTERCEPTION_TIMEOUT_SECONDS..MAX_INTERCEPTION_TIMEOUT_SECONDS) {
            storedInterceptionTimeoutSeconds = DEFAULT_INTERCEPTION_TIMEOUT_SECONDS
        }
        if (bearerToken.isBlank()) {
            bearerToken = generateBearerToken()
        }
        val current = getAutoApproveTargetsList()
        val valid = current.filter { TargetValidation.isValidTarget(it) }
        if (valid.size != current.size) {
            _autoApproveTargets = valid.joinToString(TARGET_SEPARATOR)
        }
    }

    fun addAutoApproveTarget(target: String): Boolean {
        val trimmed = target.trim()
        if (!TargetValidation.isValidTarget(trimmed)) return false
        val currentTargets = getAutoApproveTargetsList()
        if (currentTargets.contains(trimmed)) return false
        val newTargets = currentTargets + trimmed
        autoApproveTargets = newTargets.joinToString(TARGET_SEPARATOR)
        return true
    }

    fun removeAutoApproveTarget(target: String): Boolean {
        val currentTargets = getAutoApproveTargetsList()
        val newTargets = currentTargets.filter { it != target.trim() }
        if (newTargets.size != currentTargets.size) {
            autoApproveTargets = newTargets.joinToString(TARGET_SEPARATOR)
            return true
        }
        return false
    }

    fun getAutoApproveTargetsList(): List<String> {
        return if (_autoApproveTargets.isBlank()) {
            emptyList()
        } else {
            _autoApproveTargets.split(TARGET_SEPARATOR).map { it.trim() }.filter { it.isNotEmpty() }
        }
    }

    fun clearAutoApproveTargets() {
        autoApproveTargets = ""
    }

    fun addTargetsChangeListener(listener: () -> Unit): ListenerHandle {
        val registration = ListenerRegistration(listener)
        targetsChangeListeners.add(registration)
        return ListenerHandle { removeTargetsChangeListener(registration) }
    }

    private fun removeTargetsChangeListener(registration: ListenerRegistration) {
        targetsChangeListeners.remove(registration)
    }

    private fun notifyTargetsChanged() {
        cleanupStaleListeners(targetsChangeListeners)
        val listeners = targetsChangeListeners.mapNotNull { it.listener.get() }
        listeners.forEach { listener ->
            try {
                listener()
            } catch (e: Exception) {
                logging.logToError("Targets change listener failed: ${e.message}")
            }
        }
    }

    fun addDataAccessChangeListener(listener: () -> Unit): ListenerHandle {
        val registration = ListenerRegistration(listener)
        dataAccessChangeListeners.add(registration)
        return ListenerHandle { removeDataAccessChangeListener(registration) }
    }

    private fun removeDataAccessChangeListener(registration: ListenerRegistration) {
        dataAccessChangeListeners.remove(registration)
    }

    private fun notifyDataAccessChanged() {
        cleanupStaleListeners(dataAccessChangeListeners)
        val listeners = dataAccessChangeListeners.mapNotNull { it.listener.get() }
        listeners.forEach { listener ->
            try {
                listener()
            } catch (e: Exception) {
                logging.logToError("Data access change listener failed: ${e.message}")
            }
        }
    }

    private fun cleanupStaleListeners(listenerList: CopyOnWriteArrayList<ListenerRegistration>) {
        val staleListeners = listenerList.filter { it.listener.get() == null }
        listenerList.removeAll(staleListeners)
    }

    fun cleanup() {
        targetsChangeListeners.clear()
        dataAccessChangeListeners.clear()
    }

    private fun generateBearerToken(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}

fun PersistedObject.boolean(default: Boolean = false) =
    PersistedDelegate(getter = { key -> getBoolean(key) ?: default }, setter = { key, value -> setBoolean(key, value) })

fun PersistedObject.string(default: String) =
    PersistedDelegate(getter = { key -> getString(key) ?: default }, setter = { key, value -> setString(key, value) })

fun PersistedObject.int(default: Int) =
    PersistedDelegate(getter = { key -> getInteger(key) ?: default }, setter = { key, value -> setInteger(key, value) })

fun PersistedObject.stringList(default: String) =
    PersistedDelegate(getter = { key -> getString(key) ?: default }, setter = { key, value -> setString(key, value) })

class PersistedDelegate<T>(
    private val getter: (name: String) -> T, private val setter: (name: String, value: T) -> Unit
) : ReadWriteProperty<Any, T> {
    override fun getValue(thisRef: Any, property: KProperty<*>) = getter(property.name)
    override fun setValue(thisRef: Any, property: KProperty<*>, value: T) = setter(property.name, value)
}

class ListenerRegistration(listener: () -> Unit) {
    val listener: WeakReference<() -> Unit> = WeakReference(listener)
}

fun interface ListenerHandle {
    fun remove()
}
