const [clientConfig] = arguments;

const { CoreCrypto } = await import("./corecrypto.js");
window.CoreCrypto = CoreCrypto;

const cc = await CoreCrypto.init(clientConfig);

window.cc = cc;

const [kp] = await cc.clientKeypackages(1);
return kp;
