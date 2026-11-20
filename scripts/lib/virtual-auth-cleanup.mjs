// A fresh Home keeps its first owner and the virtual authenticator that can
// sign in as that owner. Guest cleanup still follows the authenticated route.
export async function cleanupVirtualPasskey(created, remove) {
  if (created?.created && created.mode === "admin") {
    return {
      ok: true,
      skipped: true,
      retained: true,
      reason: "First owner passkey kept. Add another admin passkey before removing it.",
    };
  }
  return remove();
}

export function shouldRetainVirtualAuthProfile({ created, cleanup, credentialCount, credentialSaveError }) {
  return cleanup?.retained === true || (cleanup?.ok !== true && Boolean(
    created?.created || credentialCount > 0 || credentialSaveError,
  ));
}

export function retainedFirstOwnerProfileMessage(profileDir) {
  return `First owner passkey kept. You must keep this profile and its saved authenticator: ${JSON.stringify(profileDir)}`;
}

export const VIRTUAL_AUTH_PROFILE_CLEANUP_INSTRUCTION =
  "Keep this profile while its test passkey has access to Home. To remove a first-owner passkey, add another admin passkey first. Remove the test passkey in System before deleting this profile, or dispose of an isolated test Home and its profile together. Set HOME_VIRTUAL_AUTH_PROFILE to this profile_dir and use the same HOME_URL to restore its authenticator.";
