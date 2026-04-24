function scanPage(data) {
  const findings = [];

  if (data.scripts > 15) {
    findings.push("Too many scripts detected");
  }

  if (data.passwords > 0) {
    findings.push("Password field found");
  }

  if (data.forms > 3) {
    findings.push("Multiple forms detected");
  }

  if (data.iframes > 2) {
    findings.push("Multiple iFrames found");
  }

  if (data.links > 150) {
    findings.push("Large number of links detected");
  }

  return findings;
}