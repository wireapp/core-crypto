/**
 * Data shape for proteusNewPrekeyAuto() call returns.
 */
export interface ProteusAutoPrekeyBundle {
    /**
     * Proteus PreKey id
     *
     * @readonly
     */
    id: number;
    /**
     * CBOR-serialized Proteus PreKeyBundle
     *
     * @readonly
     */
    pkb: Uint8Array;
}
