/* eslint-disable no-undef */
exports.load = function (app) {
    const logger = app.logger;

    // Monkey-patch the warn() method to suppress specific messages
    const originalWarn = logger.warn.bind(logger);
    logger.warn = (message, ...args) => {
        if (
            (typeof message === "string" &&
                message.includes("UniffiAbstractObject.uniffiDestroy")) ||
            message.includes("__type.new") ||
            message.includes("__type.create") ||
            message.includes("__type.defaults")
        ) {
            // Ignore this specific ubrn warnings
            return;
        }
        originalWarn(message, ...args);
    };
};
