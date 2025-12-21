console.log("PhishGuard Gmail Scanner Loaded");

setInterval(() => {
  let emails = document.querySelectorAll(".zA");

  emails.forEach((email) => {
    let text = email.innerText;

    fetch("http://127.0.0.1:5000/check_email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: text }),
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.result !== "safe email") {
          chrome.notifications.create({
            type: "basic",
            iconUrl: "icon.png",
            title: "PhishGuard Alert!",
            message: "Potential phishing email detected!",
          });
        }
      });
  });
}, 20000); // every 20 seconds
