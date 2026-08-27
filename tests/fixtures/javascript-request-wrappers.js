const origin = location.origin;
const publicProxy = origin + "/public";
const itsmeProxy = "https://identity.example.test";

function md(url, method, data) {
  return fetch(url, {
    method: method,
    headers: {
      "Content-Type": "application/json",
      "X-Client": "web"
    },
    credentials: "include",
    body: JSON.stringify(data)
  });
}

const postJson = (url, payload) => {
  return axios.post(url, payload, {
    headers: { "X-App-Version": "1" },
    withCredentials: true
  });
};

md(publicProxy + "/v1/PasswordLogin", "POST", {
  accountId,
  deviceId,
  oneTimeCode
});

postJson(itsmeProxy + "/status", {
  state,
  code
});

// A runtime-selected method is intentionally not guessed.
md(publicProxy + "/v1/runtime", methodFromState, { value });
