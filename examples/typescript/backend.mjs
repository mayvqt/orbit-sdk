import { OrbitBackendClient } from "../../sdk/typescript/index.mjs";

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

const orbit = new OrbitBackendClient({
  appKey: required("ORBIT_APP_KEY"),
  managementToken: required("ORBIT_MANAGEMENT_TOKEN"),
});

const decision = await orbit.decideFeature({
  customerSession: required("ORBIT_CUSTOMER_SESSION"),
  licenceId: required("ORBIT_LICENCE_ID"),
  activationId: required("ORBIT_ACTIVATION_ID"),
  entitlement: process.env.ORBIT_ENTITLEMENT || "export",
});

if (!decision.allowed) {
  console.error(`Feature denied: ${decision.reason}`);
  process.exitCode = 1;
} else {
  console.log(`Feature allowed at ${decision.checked_at}`);
}
