function calculateScore(findings) {
  let score = 100;

  findings.forEach(item => {
    if (item.includes("scripts")) score -= 10;
    if (item.includes("Password")) score -= 15;
    if (item.includes("forms")) score -= 8;
    if (item.includes("links")) score -= 5;
    if (item.includes("iFrames")) score -= 12;
  });

  if (score < 0) score = 0;

  return score;
}