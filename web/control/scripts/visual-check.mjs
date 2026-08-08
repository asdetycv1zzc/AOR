import { chromium } from "playwright";

const baseURL = process.env.AOR_WEB_URL || "http://127.0.0.1:8090/ui/";
const artifactDirectory = "visual-artifacts";
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 960 } });
const page = await context.newPage();
const errors = [];
const failedResponses = [];

page.on("pageerror", (error) => errors.push(`page: ${error.message}`));
page.on("console", (message) => {
  if (message.type() === "error") errors.push(`console: ${message.text()}`);
});
page.on("response", (response) => {
  if (response.status() >= 400) failedResponses.push(`${response.status()} ${response.url()}`);
});

async function assertNoPageOverflow(label) {
  const dimensions = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  if (dimensions.scrollWidth > dimensions.clientWidth + 1) {
    throw new Error(`${label} overflows horizontally: ${dimensions.scrollWidth}/${dimensions.clientWidth}`);
  }
}

async function clickVisible(locator) {
  if (await locator.count() && await locator.first().isVisible()) {
    await locator.first().click();
    return true;
  }
  return false;
}

try {
  await page.goto(baseURL, { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "使用本地身份登录" }).waitFor();
  await assertNoPageOverflow("desktop login");
  await page.screenshot({ path: `${artifactDirectory}/login-desktop.png`, fullPage: true });

  await page.getByRole("button", { name: "使用本地身份登录" }).click();
  for (let step = 0; step < 4 && !page.url().startsWith(baseURL); step += 1) {
    await page.waitForLoadState("domcontentloaded");
    const advanced =
      await clickVisible(page.getByRole("link", { name: /local test identity/i })) ||
      await clickVisible(page.getByRole("button", { name: /local test identity/i })) ||
      await clickVisible(page.getByRole("button", { name: /grant access|approve|allow|同意/i }));
    if (!advanced) break;
  }
  await page.waitForURL(/\/ui\//, { timeout: 15_000 });
  await page.getByRole("heading", { name: "选择一个项目开始" }).waitFor({ timeout: 15_000 });

  await page.getByRole("button", { name: "新建项目" }).first().click();
  const projectName = `webui-smoke-${Date.now()}`;
  await page.getByLabel("项目名称").fill(projectName);
  await page.getByLabel("部署目标").fill("test");
  await page.getByRole("button", { name: "创建项目" }).click();
  await page.getByRole("heading", { name: projectName }).waitFor({ timeout: 20_000 });
  await page.waitForTimeout(700);
  await assertNoPageOverflow("desktop project");
  await page.screenshot({ path: `${artifactDirectory}/project-desktop.png`, fullPage: true });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForTimeout(350);
  await assertNoPageOverflow("mobile project");
  await page.screenshot({ path: `${artifactDirectory}/project-mobile.png`, fullPage: true });

  if (errors.length > 0 || failedResponses.length > 0) {
    throw new Error([...errors, ...failedResponses.map((item) => `response: ${item}`)].join("\n"));
  }
  process.stdout.write(`visual-check ok: ${projectName}\n`);
} finally {
  await browser.close();
}
