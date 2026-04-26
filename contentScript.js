// SentinelX contentScript.js
// Final Launch Calibrated Version

console.log("SentinelX Scanner Active");

const trustedDomains = [
  "google",
  "amazon",
  "github",
  "microsoft",
  "wikipedia",
  "openai",
  "reddit",
  "apple",
  "myntra",
  "flipkart",
  "adobe",
  "spotify",
  "youtube",
  "pinterest",
  "facebook",
  "instagram",
  "linkedin",
  "netflix",
];

const protectedBrands = [
  "google",
  "amazon",
  "paypal",
  "microsoft",
  "apple",
  "facebook",
  "instagram",
  "netflix",
  "openai",
  "youtube",
  "linkedin",
  "reddit",
];

const suspiciousTlds = [".xyz", ".top", ".click", ".shop", ".buzz", ".info"];

function applyPenalty(score, amount) {
  return score - Number(amount || 0);
}
function applyBonus(score, amount) {
  return score + Number(amount || 0);
}
function clamp(score) {
  return Math.max(0, Math.min(100, score));
}

function normalizeDomain(text) {
  return text
    .toLowerCase()
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a");
}

function uniqueFindings(findings) {
  const seen = new Set();
  return findings.filter((item) => {
    if (seen.has(item.text)) return false;
    seen.add(item.text);
    return true;
  });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type !== "SCAN_PAGE") return;

  try {
    const hostLower = location.hostname.replace(/^www\./, "").toLowerCase();
    const normalizedHost = normalizeDomain(hostLower);
    const isHttps = location.protocol === "https:";

    const data = {
      url: location.href,
      title: document.title || location.hostname,
      hostname: hostLower,
      forms: document.querySelectorAll("form").length,
      inputs: document.querySelectorAll("input").length,
      passwords: document.querySelectorAll('input[type="password"]').length,
      scripts: document.querySelectorAll("script").length,
      links: document.querySelectorAll("a").length,
      iframes: document.querySelectorAll("iframe").length,
    };

    const pageText = (
      document.body?.innerText ||
      document.documentElement?.innerText ||
      ""
    )
      .slice(0, 6000)
      .toLowerCase();

    let score = 92;
    const findings = [];

    const isTrusted = trustedDomains.some((name) => hostLower.includes(name));
    const looksLikeBrand =
      !isTrusted && protectedBrands.some((name) => hostLower.includes(name));
    const typoBrand =
      !isTrusted &&
      protectedBrands.some(
        (name) => normalizedHost.includes(name) && !hostLower.includes(name),
      );

    const suspiciousHits = (
      pageText.match(
        /free download|watch free|stream free|casino|xxx|mod apk|crack/g,
      ) || []
    ).length;

    const hasSuspiciousTld = suspiciousTlds.some((tld) =>
      hostLower.endsWith(tld),
    );
    const hasLongDomain = hostLower.length > 28;
    const hasManyNumbers = (hostLower.match(/[0-9]/g) || []).length >= 4;
    const hasManyHyphens = (hostLower.match(/-/g) || []).length >= 2;

    // Domain only piracy detector (fixed false positives)
    const isPiracyStyle = /hdhub|torrent|1337x|yts|rarbg|fmovies/.test(
      hostLower,
    );

    if (isTrusted) score = applyBonus(score, 6);
    if (isHttps) score = applyBonus(score, 4);
    else {
      score = applyPenalty(score, 25);
      findings.push({ text: "Website not using HTTPS", severity: "high" });
    }

    if (!isHttps && data.passwords > 0) {
      score = applyPenalty(score, 30);
      findings.push({
        text: "Password form on insecure page",
        severity: "high",
      });
    }

    if (looksLikeBrand) {
      score = applyPenalty(score, 22);
      findings.push({ text: "Domain imitates known brand", severity: "high" });
    }

    if (typoBrand) {
      score = applyPenalty(score, 28);
      findings.push({
        text: "Typosquatting brand imitation domain detected",
        severity: "high",
      });
    }

    if (hasSuspiciousTld) {
      score = applyPenalty(score, 12);
      findings.push({
        text: "Suspicious domain ending detected",
        severity: "medium",
      });
    }

    if (hasLongDomain) {
      score = applyPenalty(score, 6);
      findings.push({ text: "Unusually long domain name", severity: "low" });
    }

    if (hasManyNumbers) {
      score = applyPenalty(score, 10);
      findings.push({ text: "Too many numbers in domain", severity: "medium" });
    }

    if (hasManyHyphens) {
      score = applyPenalty(score, 8);
      findings.push({ text: "Multiple hyphens in domain", severity: "medium" });
    }

    if (suspiciousHits >= 2) {
      score = applyPenalty(score, 18);
      findings.push({
        text: "Risky content keywords detected",
        severity: "medium",
      });
    }

    if (isPiracyStyle) {
      score = Math.min(score, 40);
      findings.push({
        text: "Piracy / suspicious download style site detected",
        severity: "high",
      });
    }

    document.querySelectorAll("iframe").forEach((frame) => {
      try {
        const style = getComputedStyle(frame);
        if (
          style.display === "none" ||
          style.visibility === "hidden" ||
          frame.width == 0 ||
          frame.height == 0
        ) {
          score = applyPenalty(score, 10);
          findings.push({ text: "Hidden iframe detected", severity: "medium" });
        }
      } catch (error) {}
    });

    if (document.querySelector('meta[http-equiv="refresh"]')) {
      score = applyPenalty(score, 12);
      findings.push({
        text: "Automatic page redirect detected",
        severity: "medium",
      });
    }

    if (
      /redirect=|url=|next=|target=/.test(location.href.toLowerCase()) &&
      !isTrusted
    ) {
      score = applyPenalty(score, 10);
      findings.push({
        text: "Suspicious redirect URL pattern detected",
        severity: "medium",
      });
    }

    const finalFindings = uniqueFindings(findings);

    // Launch calibration bands
    if (isTrusted) {
      score = Math.max(score, 82);
      score = Math.min(score, 98);
    } else {
      score = Math.min(score, 90);
    }

    // Free gaming / ad-heavy sites should not appear elite trust
    if (
      /games|play|arcade|freegames|html5/.test(hostLower + pageText) &&
      !isTrusted
    ) {
      score = Math.min(score, 82);
    }

    score = clamp(score);

    const criticalRisk = finalFindings.some(
      (item) =>
        item.text.includes("Typosquatting") ||
        item.text.includes("Domain imitates known brand") ||
        item.text.includes("Password form on insecure") ||
        item.text.includes("Piracy"),
    );

    const mediumCount = finalFindings.filter(
      (item) => item.severity === "medium",
    ).length;

    let confidenceLabel = "Caution";
    let confidenceEmoji = "⚠";

    if (score >= 78 && !criticalRisk && mediumCount <= 2) {
      confidenceLabel = "Trusted";
      confidenceEmoji = "✅";
    } else if (score < 50 || criticalRisk) {
      confidenceLabel = "Dangerous";
      confidenceEmoji = "🚨";
    }

    chrome.runtime.sendMessage({ type: "UPDATE_BADGE", score });

    sendResponse({
      ...data,
      findings: finalFindings,
      score,
      confidenceLabel,
      confidenceEmoji,
    });
  } catch (error) {
    console.error("SentinelX Scan Error:", error);
    sendResponse({
      url: location.href,
      title: document.title || location.hostname,
      findings: [],
      score: 50,
      confidenceLabel: "Caution",
      confidenceEmoji: "⚠",
    });
  }
});

window.addEventListener("load", () => {
  setTimeout(() => {
    let quickScore = location.protocol === "https:" ? 85 : 65;
    if (document.querySelectorAll('input[type="password"]').length > 0)
      quickScore -= 10;
    if (document.querySelectorAll("iframe").length > 3) quickScore -= 8;
    if (document.querySelectorAll("script").length > 20) quickScore -= 8;
    chrome.runtime.sendMessage({
      type: "UPDATE_BADGE",
      score: clamp(quickScore),
    });
  }, 1500);
});

document.addEventListener("focusin", (event) => {
  const target = event.target;
  if (target.tagName === "INPUT" && target.type === "password") {
    if (location.protocol !== "https:") {
      if (document.getElementById("sentinelxWarn")) return;
      const banner = document.createElement("div");
      banner.id = "sentinelxWarn";
      banner.innerText = "⚠ SentinelX: This page may be unsafe for passwords.";
      Object.assign(banner.style, {
        position: "fixed",
        top: "15px",
        right: "15px",
        zIndex: "999999",
        background: "#ff3b30",
        color: "white",
        padding: "12px 16px",
        borderRadius: "12px",
        fontSize: "14px",
        fontWeight: "600",
        boxShadow: "0 6px 18px rgba(0,0,0,0.25)",
      });
      document.body.appendChild(banner);
      setTimeout(() => banner.remove(), 5000);
    }
  }
});
