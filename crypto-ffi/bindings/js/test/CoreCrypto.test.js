const puppeteer = require("puppeteer");

async function initBrowser(){
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.goto("http://localhost:3000");
  return page;
}

test("init", async () => {
  const page = await initBrowser();

  const version = await page.evaluate(async () => {
    const { CoreCrypto } = await import("./corecrypto.js");

    const cc = await CoreCrypto.init({
      path: "test",
      key: "test",
      clientId: "test",
    });

    return CoreCrypto.version();
  });
  expect(version).toBe("0.2.0");
});

test("get client public key", async () => {
  const page = await initBrowser();

  const pkLength = await page.evaluate(async () => {
    const { CoreCrypto } = await import("./corecrypto.js");

    const cc = await CoreCrypto.init({
      path: "test",
      key: "test",
      clientId: "test",
    });

    return cc.clientPublicKey().length;
  });
  expect(pkLength).toBe(32);
});

test("get client keypackages", async () => {
  const page = await initBrowser();

  const kpNumber = await page.evaluate(async () => {
    const { CoreCrypto } = await import("./corecrypto.js");

    const cc = await CoreCrypto.init({
      path: "test",
      key: "test",
      clientId: "test",
    });

    return cc.clientKeypackages(20).length;
  });
  expect(kpNumber).toBe(20);
});

test("encrypt message", async () => {
  const page = await initBrowser();

  const msgLen = await page.evaluate(async () => {
    const { CoreCrypto } = await import("./corecrypto.js");

    const cc = await CoreCrypto.init({
      path: "test",
      key: "test",
      clientId: "test",
    });

    const conversationId = "testConversation";

    cc.createConversation(conversationId, {});

    return cc.encryptMessage(
      conversationId,
      new TextEncoder().encode("Hello World!")
    ).length;
  });
  expect(msgLen).toBeGreaterThan(0);
});

test("roundtrip message", async () => {
  const page = await initBrowser();

  const ret = await page.evaluate(async () => {
    const { CoreCrypto } = await import("./corecrypto.js");

    const dummy = await CoreCrypto.init({ path: "dummy", key: "dummy", clientId: "dummy"});

    const cc = await CoreCrypto.init({
      path: "test",
      key: "test",
      clientId: "test",
    });

    const cc2 = await CoreCrypto.init({
      path: "test2",
      key: "test2",
      clientId: "test2",
    });

    const [kp] = cc2.clientKeypackages(1);

    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    const conversationId = "testConversation";

    cc.createConversation(conversationId, {});

    const welcome = cc.addClientsToConversation(conversationId, [
      { id: encoder.encode("test2"), kp: kp },
    ]);

    if (!welcome) {
      throw new Error("no welcome message was generated");
    }

    const welcomeConversationId = decoder.decode(
      cc2.processWelcomeMessage(welcome.welcome)
    );
    if (conversationId !== welcomeConversationId) {
      throw new Error("conversationId mismatch");
    }

    const messageText = "Hello World!";

    const message = cc.encryptMessage(
      conversationId,
      new TextEncoder().encode(messageText)
    );

    const decryptedMessage = new TextDecoder().decode(
      cc2.decryptMessage(conversationId, message)
    );

    if (decryptedMessage !== messageText) {
      throw new Error("message mismatch");
    }

    return true;
  });
  expect(ret).toBe(true);
});
