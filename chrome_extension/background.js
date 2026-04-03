const API_URL = "http://127.0.0.1:5000/check_url";

const WHITELIST = [
  "google.com", "youtube.com", "github.com",
  "microsoft.com", "localhost", "127.0.0.1"
];

function isWhitelisted(url) {
  return WHITELIST.some(domain => url.includes(domain));
}

chrome.webNavigation.onCompleted.addListener(async (details) => {
  const url = details.url;

  if (!url.startsWith("http")) return;
  if (isWhitelisted(url)) return;

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });

    const data = await response.json();

    if (data.result === "PHISHING") {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icon.png",
        title: "PhishGuard Alert!",
        message: "Phishing URL Detected!\n" + url.substring(0, 60)
      });
    }

  } catch (error) {
    console.log("API not running:", error);
  }
});