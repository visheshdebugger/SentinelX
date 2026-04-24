function extractPageData() {
  return {
    url: window.location.href,
    title: document.title,

    forms: document.querySelectorAll("form").length,
    inputs: document.querySelectorAll("input").length,
    passwords: document.querySelectorAll('input[type="password"]').length,

    scripts: document.querySelectorAll("script").length,
    links: document.querySelectorAll("a").length,
    iframes: document.querySelectorAll("iframe").length
  };
}