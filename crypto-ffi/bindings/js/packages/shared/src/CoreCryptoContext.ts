import { CoreCryptoContext as CoreCryptoContextFfi } from "#core-crypto-ffi";
export class CoreCryptoContext extends CoreCryptoContextFfi {
    /** @internal */
    constructor(ctx: CoreCryptoContextFfi) {
        super(ctx);
    }

    /** @internal */
    static instanceOf(obj: unknown): obj is CoreCryptoContextFfi {
        return super.instanceOf(obj);
    }
}
