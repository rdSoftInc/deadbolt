const origin = window.location.origin;
const environmentPrefix = "/public";
const publicProxy = origin + environmentPrefix;
const rootDomain = "example.test";
const apiHost = `https://itsme.${rootDomain}`;
const config = { statusBase: apiHost };

fetch(publicProxy + "/v1/PasswordLogin", {
  method: "POST",
  body: JSON.stringify({ accountId, deviceId, oneTimeCode })
});
axios.post(`${publicProxy}/v1/FederatedLogin`, {
  state,
  code,
  error,
  errorDescription
});
fetch(config.statusBase + "/status", { method: "POST" });

const request = new XMLHttpRequest();
request.open("POST", apiHost + "/GetClockChallenge", true);

// Dynamic expressions must remain unresolved rather than guessed.
fetch(publicProxy + routeFromRuntime);
