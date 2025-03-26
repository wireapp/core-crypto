export interface CoreCryptoRichError {
    message: string;
    error_name?: string;
    error_stack?: string[];
    proteus_error_code?: number;
}

/**
 * Error wrapper that takes care of extracting rich error details across the FFI (through JSON parsing)
 *
 * Whenever you're supposed to get this class (that extends `Error`) you might end up with a base `Error`
 * in case the parsing of the message structure fails. This is unlikely but the case is still covered and fall backs automatically.
 * More information will be found in the base `Error.cause` to inform you why the parsing has failed.
 *
 * Please note that in this case the extra properties will not be available.
 */
export class CoreCryptoError extends Error {
    errorStack: string[];
    proteusErrorCode: number | null;

    /* eslint @typescript-eslint/no-explicit-any: off */
    private constructor(richError: CoreCryptoRichError, ...params: any[]) {
        super(richError.message, ...params);
        Object.setPrototypeOf(this, new.target.prototype);

        if (richError.error_name) {
            this.name = richError.error_name;
        }
        if (richError.error_stack) {
            this.errorStack = richError.error_stack;
        } else {
            this.errorStack = [];
        }
        if (richError.proteus_error_code) {
            this.proteusErrorCode = richError.proteus_error_code;
        } else {
            this.proteusErrorCode = null;
        }
    }

    private static fallback(msg: string, ...params: any[]): Error {
        console.warn(
            `Cannot build CoreCryptoError, falling back to standard Error! ctx: ${msg}`
        );
        return new Error(msg, ...params);
    }

    static build(msg: string, ...params: unknown[]): CoreCryptoError | Error {
        try {
            const richError: CoreCryptoRichError = JSON.parse(msg);
            return new this(richError, ...params);
        } catch {
            return this.fallback(msg, ...params);
        }
    }

    static fromStdError(e: Error): CoreCryptoError | Error {
        if (e instanceof CoreCryptoError) {
            return e;
        }
        const opts = {
            cause: e.cause || undefined,
            stack: e.stack || undefined,
        };

        return this.build(e.message, opts);
    }

    static async asyncMapErr<T>(p: Promise<T>): Promise<T> {
        const mappedErrorPromise = p.catch((e: Error | CoreCryptoError) => {
            if (e instanceof CoreCryptoError) {
                throw e;
            } else {
                throw this.fromStdError(e);
            }
        });

        return await mappedErrorPromise;
    }
}
