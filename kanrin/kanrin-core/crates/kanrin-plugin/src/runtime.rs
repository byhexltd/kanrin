use std::path::Path;
use std::sync::Arc;

use thiserror::Error;
use wasmtime::*;

use crate::api::{PluginEvent, PluginHook, PluginManifest, PluginResponse};

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("failed to load plugin: {0}")]
    LoadFailed(String),

    #[error("plugin execution error: {0}")]
    ExecutionError(String),

    #[error("invalid manifest: {0}")]
    InvalidManifest(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),
}

/// A loaded WASM plugin instance.
pub struct Plugin {
    pub manifest: PluginManifest,
    instance: Instance,
    store: Store<PluginState>,
}

/// Per-plugin state accessible from within WASM.
struct PluginState {
    /// Buffer for data exchange between host and WASM.
    shared_buffer: Vec<u8>,
}

impl Plugin {
    /// Invoke a hook on this plugin.
    pub fn invoke(&mut self, hook: PluginHook, event: &PluginEvent) -> Result<PluginResponse, PluginError> {
        if !self.manifest.hooks.contains(&hook) {
            return Ok(PluginResponse::Pass);
        }

        // Serialize event to JSON, write to shared memory
        let event_json = serde_json::to_vec(event)
            .map_err(|e| PluginError::ExecutionError(format!("serialize event: {}", e)))?;

        // Get WASM memory
        let memory = self.instance.get_memory(&mut self.store, "memory")
            .ok_or_else(|| PluginError::ExecutionError("no memory export".into()))?;

        // Write event to WASM memory at offset 0
        let event_len = event_json.len();
        if event_len > 65536 {
            return Err(PluginError::ExecutionError("event too large".into()));
        }

        memory.write(&mut self.store, 0, &event_json)
            .map_err(|e| PluginError::ExecutionError(format!("memory write: {}", e)))?;

        // Call the hook function
        let hook_name = match hook {
            PluginHook::PreEncrypt => "on_pre_encrypt",
            PluginHook::PostDecrypt => "on_post_decrypt",
            PluginHook::RouteDecision => "on_route",
            PluginHook::OnConnect => "on_connect",
            PluginHook::OnDisconnect => "on_disconnect",
            PluginHook::OnTick => "on_tick",
        };

        let func = self.instance.get_typed_func::<(i32, i32), i32>(&mut self.store, hook_name)
            .map_err(|_| PluginError::ExecutionError(format!("function '{}' not found", hook_name)))?;

        let result_len = func.call(&mut self.store, (0, event_len as i32))
            .map_err(|e| PluginError::ExecutionError(format!("call {}: {}", hook_name, e)))?;

        if result_len <= 0 {
            return Ok(PluginResponse::Pass);
        }

        // Read response from WASM memory
        let mut response_buf = vec![0u8; result_len as usize];
        memory.read(&self.store, 0, &mut response_buf)
            .map_err(|e| PluginError::ExecutionError(format!("read response: {}", e)))?;

        let response: PluginResponse = serde_json::from_slice(&response_buf)
            .map_err(|e| PluginError::ExecutionError(format!("deserialize response: {}", e)))?;

        Ok(response)
    }
}

/// Manages loading and running multiple plugins.
pub struct PluginRuntime {
    engine: Engine,
    plugins: Vec<Plugin>,
}

impl PluginRuntime {
    pub fn new() -> Result<Self, PluginError> {
        let mut config = Config::new();
        // Sandbox: disable WASI filesystem, networking, etc.
        config.wasm_bulk_memory(true);
        config.cranelift_opt_level(OptLevel::Speed);

        let engine = Engine::new(&config)
            .map_err(|e| PluginError::LoadFailed(format!("engine init: {}", e)))?;

        Ok(Self {
            engine,
            plugins: Vec::new(),
        })
    }

    /// Load a plugin from a .wasm file.
    pub fn load_plugin(&mut self, wasm_path: &Path, manifest: PluginManifest) -> Result<(), PluginError> {
        let module = Module::from_file(&self.engine, wasm_path)
            .map_err(|e| PluginError::LoadFailed(format!("compile: {}", e)))?;

        let mut store = Store::new(&self.engine, PluginState {
            shared_buffer: Vec::new(),
        });

        // Create linker with host functions
        let mut linker = Linker::new(&self.engine);

        // Provide log function to WASM
        linker.func_wrap("env", "log", |mut caller: Caller<'_, PluginState>, ptr: i32, len: i32| {
            if let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) {
                let mut buf = vec![0u8; len as usize];
                if memory.read(&caller, ptr as usize, &mut buf).is_ok() {
                    if let Ok(msg) = std::str::from_utf8(&buf) {
                        tracing::debug!(plugin = "wasm", "{}", msg);
                    }
                }
            }
        }).map_err(|e| PluginError::LoadFailed(format!("linker: {}", e)))?;

        let instance = linker.instantiate(&mut store, &module)
            .map_err(|e| PluginError::LoadFailed(format!("instantiate: {}", e)))?;

        tracing::info!(
            name = %manifest.name,
            version = %manifest.version,
            hooks = ?manifest.hooks,
            "plugin loaded"
        );

        self.plugins.push(Plugin {
            manifest,
            instance,
            store,
        });

        Ok(())
    }

    /// Invoke a hook on all plugins that implement it.
    pub fn invoke_all(&mut self, hook: PluginHook, event: &PluginEvent) -> Vec<PluginResponse> {
        let mut responses = Vec::new();

        for plugin in &mut self.plugins {
            match plugin.invoke(hook, event) {
                Ok(response) => responses.push(response),
                Err(e) => {
                    tracing::warn!(
                        plugin = %plugin.manifest.name,
                        error = %e,
                        "plugin hook failed"
                    );
                }
            }
        }

        responses
    }

    /// Number of loaded plugins.
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    /// Get loaded plugin names.
    pub fn plugin_names(&self) -> Vec<&str> {
        self.plugins.iter().map(|p| p.manifest.name.as_str()).collect()
    }
}
