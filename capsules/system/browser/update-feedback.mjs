export function backgroundSettingState(background) {
  return JSON.stringify({ enabled: background?.enabled, readable: background?.readable, message: background?.message });
}

export function runtimeUpdateStatusMessage(message, update, saveError, saveState) {
  const currentSaveError = saveError
    && backgroundSettingState(update?.background_checks) === saveState;
  return message === update?.background_checks?.message && !currentSaveError ? "" : message;
}
