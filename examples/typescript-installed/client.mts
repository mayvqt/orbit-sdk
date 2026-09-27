import { Client, NotActivatedError } from "../../sdk/typescript-installed/index.mjs";

export async function useInstalledClient(appKey: string, readKeyInTrustedUi: () => Promise<string | null>) {
  const client = await Client.open(appKey);
  try {
    // Resolves only when the licence includes "export"; otherwise it throws.
    const access = await client.ensureAccess("export", readKeyInTrustedUi);
    if (access.session) {
      console.info("Floating session expires at", access.session.expiresAt.toISOString());
    }
    return access;
  } catch (error) {
    if (error instanceof NotActivatedError) return null;
    throw error;
  } finally {
    await client.close();
  }
}
