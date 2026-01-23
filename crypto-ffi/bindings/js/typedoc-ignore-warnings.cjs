/* eslint-disable no-undef */
exports.load = function (app) {
    const logger = app.logger;

    function patch(obj, funcName, newFunc) {
        const originalFunc = obj[funcName].bind(obj);
        obj[funcName] = (...args) => {
            return newFunc(originalFunc, ...args);
        };
    }

    function suppressUniffiWarnings(originalFunc, message, ...args) {
        if (
            (typeof message === "string" &&
                (message.includes("UniffiAbstractObject.uniffiDestroy") ||
                    message.includes("__type.new") ||
                    message.includes("__type.create") ||
                    message.includes("__type.defaults"))) ||
            message.includes("PkiEnvironmentHooksError.__type")
        ) {
            // Ignore these specific ubrn warnings
            return;
        }
        originalFunc(message, ...args);
    }

    // Monkey-patch these two methods to suppress specific messages
    patch(logger, "warn", suppressUniffiWarnings);
    patch(logger, "validationWarning", suppressUniffiWarnings);
};
