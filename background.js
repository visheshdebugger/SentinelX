const warnedTabs = {};

chrome.runtime.onMessage.addListener((request, sender) => {
  if (request.type === "UPDATE_BADGE") {
    const tabId = sender.tab?.id;

    if (!tabId) return;

    // -----------------------------
    // RISK
    // -----------------------------
    if (request.score < 55) {
      chrome.action.setBadgeText({
        text: "RISK",
        tabId: tabId,
      });

      chrome.action.setBadgeBackgroundColor({
        color: "#ff3b30",
        tabId: tabId,
      });

      // One warning per tab
      if (!warnedTabs[tabId]) {
        warnedTabs[tabId] = true;

        chrome.notifications.create({
          type: "basic",
          iconUrl: "icon128.png",
          title: "⚠ SentinelX Warning",
          message:
            "This website may be risky. Be careful with passwords or payments.",
        });
      }
    }

    // -----------------------------
    // CARE
    // -----------------------------
    else if (request.score < 75) {
      chrome.action.setBadgeText({
        text: "CARE",
        tabId: tabId,
      });

      chrome.action.setBadgeBackgroundColor({
        color: "#ff9500",
        tabId: tabId,
      });
    }

    // -----------------------------
    // OK
    // -----------------------------
    else {
      chrome.action.setBadgeText({
        text: "OK",
        tabId: tabId,
      });

      chrome.action.setBadgeBackgroundColor({
        color: "#34c759",
        tabId: tabId,
      });
    }
  }
});

// Reset warning memory when tab reloads / changes page
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    delete warnedTabs[tabId];
  }
});
