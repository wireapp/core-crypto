/**
 * The error structure produced by our rust code.
 **/
export interface CoreCryptoRichError<T extends ErrorType> {
    message: string;
    error_name?: string;
    error_stack?: string[];
    type?: T;
    context?: ErrorContext[T];
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
export class CoreCryptoError<T extends ErrorType> extends Error {
    errorStack: string[];
    context?: ErrorContext[T];
    type?: T;

    /* eslint @typescript-eslint/no-explicit-any: off */
    private constructor(richError: CoreCryptoRichError<T>, ...params: any[]) {
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
        if (
            richError.context &&
            richError.type &&
            Object.values<string>(ErrorType).includes(richError.type)
        ) {
            this.context = richError.context;
            this.type = richError.type as T;
        }
    }

    private static fallback<E extends ErrorType>(
        message: string,
        ...params: any[]
    ): CoreCryptoError<E> {
        return new CoreCryptoError({ message }, ...params);
    }

    static build<E extends ErrorType>(
        msg: string,
        ...params: unknown[]
    ): CoreCryptoError<E> {
        try {
            const richError: CoreCryptoRichError<E> = JSON.parse(msg);
            return new this(richError, ...params);
        } catch {
            return this.fallback(msg, ...params);
        }
    }

    static fromStdError(e: Error): CoreCryptoError<ErrorType> {
        if (isCcErrorGeneric(e)) {
            return e;
        }
        const opts = {
            cause: e.cause || undefined,
            stack: e.stack || undefined,
        };

        return this.build(e.message, opts);
    }

    static async asyncMapErr<T, E extends ErrorType>(
        p: Promise<T>
    ): Promise<T> {
        const mappedErrorPromise = p.catch((e: Error | CoreCryptoError<E>) => {
            if (isCcErrorGeneric(e)) {
                throw e;
            } else {
                throw this.fromStdError(e);
            }
        });

        return await mappedErrorPromise;
    }
}

/**
 * Helper type to ensure that error contexts match their type
 */
export type ErrorTypeWithContext<T> = {
    [K in keyof T]: { type: K; context: T[K] };
}[keyof T];

/**
 * Variants of core crypto errors
 */
export enum ErrorType {
    Mls = "Mls",
    Proteus = "Proteus",
    E2ei = "E2ei",
    TransactionFailed = "TransactionFailed",
    Other = "Other",
}

function isCcErrorGeneric(error: unknown): error is CoreCryptoError<ErrorType> {
    return (
        typeof error === "object" &&
        error !== null &&
        "errorStack" in error &&
        "context" in error &&
        "type" in error
    );
}

export function isCcError<E extends ErrorType>(
    error: unknown,
    errorType: E
): error is CoreCryptoError<E> {
    return isCcErrorGeneric(error) && error.type === errorType;
}

/**
 * Structured core crypto error
 */
export interface ErrorContext {
    [ErrorType.Mls]: ErrorTypeWithContext<MlsErrorContext>;
    [ErrorType.Proteus]: ErrorTypeWithContext<ProteusErrorContext>;
    [ErrorType.E2ei]: { e2eiError: string };
    [ErrorType.TransactionFailed]: { error: string };
    [ErrorType.Other]: { msg: string };
}

export function isE2eiError(
    error: unknown
): error is CoreCryptoError<ErrorType.E2ei> {
    return isCcError(error, ErrorType.E2ei);
}

export function isTransactionFailedError(
    error: unknown
): error is CoreCryptoError<ErrorType.TransactionFailed> {
    return isCcError(error, ErrorType.TransactionFailed);
}

export function isOtherError(
    error: unknown
): error is CoreCryptoError<ErrorType.Other> {
    return isCcError(error, ErrorType.Other);
}

/**
 * Variants of core crypto mls errors
 */
export enum MlsErrorType {
    ConversationAlreadyExists = "ConversationAlreadyExists",
    DuplicateMessage = "DuplicateMessage",
    BufferedFutureMessage = "BufferedFutureMessage",
    WrongEpoch = "WrongEpoch",
    BufferedCommit = "BufferedCommit",
    MessageEpochTooOld = "MessageEpochTooOld",
    SelfCommitIgnored = "SelfCommitIgnored",
    UnmergedPendingGroup = "UnmergedPendingGroup",
    StaleProposal = "StaleProposal",
    StaleCommit = "StaleCommit",
    /**
     * This happens when the DS cannot flag KeyPackages as claimed or not. In this scenario, a client
     * requests their old KeyPackages to be deleted but one has already been claimed by another client to create a Welcome.
     * In that case the only solution is that the client receiving such a Welcome tries to join the group
     * with an External Commit instead
     */
    OrphanWelcome = "OrphanWelcome",
    MessageRejected = "MessageRejected",
    Other = "Other",
}

/**
 * Structured core crypto mls error (embedded in a core crypto error)
 */
export interface MlsErrorContext {
    [MlsErrorType.ConversationAlreadyExists]: { conversationId: Array<number> };
    [MlsErrorType.DuplicateMessage]: Record<string, never>;
    [MlsErrorType.BufferedFutureMessage]: Record<string, never>;
    [MlsErrorType.WrongEpoch]: Record<string, never>;
    [MlsErrorType.BufferedCommit]: Record<string, never>;
    [MlsErrorType.MessageEpochTooOld]: Record<string, never>;
    [MlsErrorType.SelfCommitIgnored]: Record<string, never>;
    [MlsErrorType.UnmergedPendingGroup]: Record<string, never>;
    [MlsErrorType.StaleProposal]: Record<string, never>;
    [MlsErrorType.StaleCommit]: Record<string, never>;
    [MlsErrorType.OrphanWelcome]: Record<string, never>;
    [MlsErrorType.MessageRejected]: { reason: string };
    [MlsErrorType.Other]: { msg: string };
}

export function isMlsError<E extends MlsErrorType>(
    error: unknown,
    errorType: E
): error is CoreCryptoError<ErrorType.Mls> & {
    context: Extract<ErrorContext[ErrorType.Mls], { type: E }>;
} {
    return (
        isCcError(error, ErrorType.Mls) &&
        error.context !== undefined &&
        error.context.type === errorType
    );
}

export function isMlsConversationAlreadyExistsError(
    error: unknown
): error is CoreCryptoError<ErrorType.Mls> & {
    context: Extract<
        ErrorContext[ErrorType.Mls],
        { type: MlsErrorType.ConversationAlreadyExists }
    >;
} {
    return isMlsError(error, MlsErrorType.ConversationAlreadyExists);
}

export function isMlsDuplicateMessageError(
    error: unknown
): error is CoreCryptoError<ErrorType.Mls> & {
    context: Extract<
        ErrorContext[ErrorType.Mls],
        { type: MlsErrorType.DuplicateMessage }
    >;
} {
    return isMlsError(error, MlsErrorType.DuplicateMessage);
}

export function isMlsBufferedFutureMessageError(
    error: unknown
): error is CoreCryptoError<ErrorType.Mls> & {
    context: Extract<
        ErrorContext[ErrorType.Mls],
        { type: MlsErrorType.BufferedFutureMessage }
    >;
} {
    return isMlsError(error, MlsErrorType.BufferedFutureMessage);
}

export function isMlsWrongEpochError(
    error: unknown
): error is CoreCryptoError<ErrorType.Mls> & {
    context: Extract<
        ErrorContext[ErrorType.Mls],
        { type: MlsErrorType.WrongEpoch }
    >;
} {
    return isMlsError(error, MlsErrorType.WrongEpoch);
}

export function isMlsBufferedCommitError(
    error: unknown
): error is CoreCryptoError<ErrorType.Mls> & {
    context: Extract<
        ErrorContext[ErrorType.Mls],
        { type: MlsErrorType.BufferedCommit }
    >;
} {
    return isMlsError(error, MlsErrorType.BufferedCommit);
}

export function isMlsSelfCommitIgnoredError(
    error: unknown
): error is CoreCryptoError<ErrorType.Mls> & {
    context: Extract<
        ErrorContext[ErrorType.Mls],
        { type: MlsErrorType.SelfCommitIgnored }
    >;
} {
    return isMlsError(error, MlsErrorType.SelfCommitIgnored);
}

export function isMlsUnmergedPendingGroupError(
    error: unknown
): error is CoreCryptoError<ErrorType.Mls> & {
    context: Extract<
        ErrorContext[ErrorType.Mls],
        { type: MlsErrorType.UnmergedPendingGroup }
    >;
} {
    return isMlsError(error, MlsErrorType.UnmergedPendingGroup);
}

export function isMlsStaleProposalError(
    error: unknown
): error is CoreCryptoError<ErrorType.Mls> & {
    context: Extract<
        ErrorContext[ErrorType.Mls],
        { type: MlsErrorType.StaleProposal }
    >;
} {
    return isMlsError(error, MlsErrorType.StaleProposal);
}

export function isMlsStaleCommitError(
    error: unknown
): error is CoreCryptoError<ErrorType.Mls> & {
    context: Extract<
        ErrorContext[ErrorType.Mls],
        { type: MlsErrorType.StaleCommit }
    >;
} {
    return isMlsError(error, MlsErrorType.StaleCommit);
}

export function isMlsOrphanWelcomeError(
    error: unknown
): error is CoreCryptoError<ErrorType.Mls> & {
    context: Extract<
        ErrorContext[ErrorType.Mls],
        { type: MlsErrorType.OrphanWelcome }
    >;
} {
    return isMlsError(error, MlsErrorType.OrphanWelcome);
}

export function isMlsMessageRejectedError(
    error: unknown
): error is CoreCryptoError<ErrorType.Mls> & {
    context: Extract<
        ErrorContext[ErrorType.Mls],
        { type: MlsErrorType.MessageRejected }
    >;
} {
    return isMlsError(error, MlsErrorType.MessageRejected);
}

export function isMlsOtherError(
    error: unknown
): error is CoreCryptoError<ErrorType.Mls> & {
    context: Extract<ErrorContext[ErrorType.Mls], { type: MlsErrorType.Other }>;
} {
    return isMlsError(error, MlsErrorType.Other);
}

/**
 * Variants of core crypto proteus errors
 */
export enum ProteusErrorType {
    SessionNotFound = "SessionNotFound",
    DuplicateMessage = "DuplicateMessage",
    RemoteIdentityChanged = "RemoteIdentityChanged",
    Other = "Other",
}

/**
 * Structured core crypto proteus error (embedded in a core crypto error)
 */
export interface ProteusErrorContext {
    [ProteusErrorType.SessionNotFound]: { errorCode: number };
    [ProteusErrorType.DuplicateMessage]: { errorCode: number };
    [ProteusErrorType.RemoteIdentityChanged]: { errorCode: number };
    [ProteusErrorType.Other]: { errorCode: number };
}

export function isProteusError<E extends ProteusErrorType>(
    error: unknown,
    errorType: E
): error is CoreCryptoError<ErrorType.Proteus> & {
    context: Extract<ErrorContext[ErrorType.Proteus], { type: E }>;
} {
    return (
        isCcError(error, ErrorType.Proteus) &&
        error.context !== undefined &&
        error.context.type === errorType
    );
}

export function isProteusSessionNotFoundError(
    error: unknown
): error is CoreCryptoError<ErrorType.Proteus> & {
    context: Extract<
        ErrorContext[ErrorType.Proteus],
        { type: ProteusErrorType.SessionNotFound }
    >;
} {
    return isProteusError(error, ProteusErrorType.SessionNotFound);
}

export function isProteusDuplicateMessageError(
    error: unknown
): error is CoreCryptoError<ErrorType.Proteus> & {
    context: Extract<
        ErrorContext[ErrorType.Proteus],
        { type: ProteusErrorType.DuplicateMessage }
    >;
} {
    return isProteusError(error, ProteusErrorType.DuplicateMessage);
}

export function isProteusRemoteIdentityChangedError(
    error: unknown
): error is CoreCryptoError<ErrorType.Proteus> & {
    context: Extract<
        ErrorContext[ErrorType.Proteus],
        { type: ProteusErrorType.RemoteIdentityChanged }
    >;
} {
    return isProteusError(error, ProteusErrorType.RemoteIdentityChanged);
}

export function isProteusOtherError(
    error: unknown
): error is CoreCryptoError<ErrorType.Proteus> & {
    context: Extract<
        ErrorContext[ErrorType.Proteus],
        { type: ProteusErrorType.Other }
    >;
} {
    return isProteusError(error, ProteusErrorType.Other);
}
