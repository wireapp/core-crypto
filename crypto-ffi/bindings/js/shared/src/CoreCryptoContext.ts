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

    /**
     * Creates a new Proteus prekey with the given ID and returns its CBOR-serialized bundle.
     *
     * Fails if the ID is already in use. Prekeys are not replaceable: the ID has been published to
     * peers in a bundle, and overwriting it would strand anyone still holding that bundle. Use
     * `proteus_new_prekey_auto` to have a free ID chosen instead.
     *
     * Warning: the Proteus client must be initialized with `proteus_init` first or an error will be returned.
     *
     * @deprecated Use {@link CoreCryptoContext.proteusNewPrekeyAuto} instead.
     */
    // We're just overriding this to deprecrate it.
    public proteusNewPrekey(
        prekeyId: number,
        asyncOpts_?: { signal: AbortSignal }
    ): Promise<Uint8Array> {
        return super.proteusNewPrekey(prekeyId, asyncOpts_);
    }
}
