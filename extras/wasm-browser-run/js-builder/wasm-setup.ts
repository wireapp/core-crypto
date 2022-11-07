const wrapConsoleMethod = method => {
    const eventName = `on_console_${method}`;
    const og = console[method];
    console[method] = function(...args) {
        const event = new CustomEvent(eventName, { detail: { ...args } } )
        window.dispatchEvent(event);
        og.apply(this, args);
    };
};

["debug", "log", "info", "warn", "error"].forEach(wrapConsoleMethod);

window.__wbg_test_invoke = f => f();
